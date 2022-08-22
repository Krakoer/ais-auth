import requests
from requests.exceptions import ConnectionError
import json
import sys
import subprocess
from hashlib import sha256
import zmq
import pyais
import threading
import os
import shutil
from tsai import TsaiUser
import time
from minilogger import *
import random
from ais_serial import AISerial

class Client:
    def __init__(self, mmsi, KGC_url, KGC_id, LO_url, auth=True, verify=True, simulate = True, param_path="a.param", debug=False, cleanup=False, dont_listen=False, sign_every=10, retransmit=False, flag_unauth=False):
        if type(mmsi) == int:
            mmsi = str(mmsi)
        assert(type(mmsi) == str)
        self.mmsi = mmsi
        self.ID_h = sha256(self.mmsi.encode("ascii")).hexdigest()

        self.buffer = {}            # Buffer for msg to verify
        self.fragment_buffer = []   # Buffer for multipart msg

        self.KGC_server_url = KGC_url
        self.KGC_id = KGC_id
        self.KGC_id_h = sha256(KGC_id.encode("ascii")).hexdigest()
        self.LO_url = LO_url
        
        self.tsai = TsaiUser(param_path)            # Crypto instance to sign
        self.tsai_verify = TsaiUser(param_path)     # Crypto instance to verify
        self.public_key = {}                        # Quick access to our public key when requested      

        self.time_threshold = 30    # Number of seconds to detect replay attack

        self.public_key_repo = {}   # Keys : MMSIs, values : public keys
        self.user_KGC_repo = {}     # Keys : MMSIs, values : KGC id
        self.KGC_pk_repo = {}       # Keys : KGC_id, value : KGC public param

        self.auth = auth            # Should we sign messages ?
        self.verify = verify        # Should we verify messages ?
        self.simulate = simulate    # Radio com or ZMQ
        self.retransmit = retransmit
        self.flag_unauth = flag_unauth
        if not self.simulate:
            self.aiserial = AISerial(dont_listen=dont_listen, retransmit=retransmit)

        self.debug = debug
        self.sign_every = sign_every    # Sign every x type1 messages
        self.not_signed = sign_every    # How many messages we sent without a signature (initialize to sign_every so the first message will be signed)

        self.authenticated = {}         # When receiving an auth type 1, the mmsi gets automatically authenticated during 5 minutes


    # To simplify debugging
    def _exit_err(self, err):
        logger.log(f"[{self.mmsi}]: {err}. ABORTING", logger.FAIL)
        exit(1)
    def _err(self, err):
        logger.log(f"[{self.mmsi}]: {err}", logger.FAIL)
    def _info(self, msg):
        logger.log(f"[{self.mmsi}]: {msg}", logger.INFO)
    def _dbg(self, msg):
        if self.debug:
            self._info(msg)

    def _is_auth(self, mmsi):
        """
        returns true if a user is auth since less than 5 minutes, otherwise false and remove user from authenticate buffer
        """
        if mmsi in self.authenticated:
            auth_time = self.authenticated[mmsi]
            # Check timing
            if time.time() >= auth_time and abs(time.time() - auth_time) <= 5*60:
                return True
            self.authenticated.pop(mmsi)

        return False
        

    def _garbage_collector_thread(self):
        # Every 1 second, check if messages have no signature for more than 10 seconds and sends them with [UNAUTH] flag
        while True:
            for msg_id, msg_dict in self.buffer.items():
                if time.time() - msg_dict["time"] >= 10: # If the message hanged there for more than 10 seconds without auth
                    # If user is auth drop it, otherwise send with flag
                    decoded = pyais.decode(msg_dict["msg"]).asdict()
                    if decoded["msg_type"] == 1 and self._is_auth(decoded["mmsi"]):
                        self.buffer.drop(msg_id)
                    else:
                        msg_5 = pyais.encode_dict({"msg_type":5, "mmsi": decoded["mmsi"], "shipname":"[UNAUTH]"})
                        if self.retransmit and not self.simulate:
                            for m in msg_5:
                                self.aiserial.retransmit(m)
                        self.aiserial.retransmit(msg_dict["msg"])


            time.sleep(1)

    def setup(self):
        """
        Function to setup the crypto, and eventually register to the KGC
        """
        self._dbg("Start setup")
        # Step 1 : try create our personal folder
        try:
            os.mkdir(self.ID_h)
        except FileExistsError:
            pass
        
        # Step 2 : If simulate, setup ZMQ
        if self.simulate:
            self.setupZMQ()
            self._dbg("ZMQ setup ok")

        # Step 3 : Update and save repos
        try:
            self.update_repos()
            self.save_repos()
            self._dbg("Update repos ok")
        except ConnectionError:
            self._dbg("Cannot connect to LO, trying to read from files")
            try:
                self.load_repos()
                self._dbg("Loaded repos from files ok")
            except Exception as e:
                self._exit_err(f"Fail to load repo from file : {e}")
        except Exception as e:
            self._exit_err(f"Fail to update and save repos : {e}")
        
        # Step 4 : Init cryptosystem with out KGC public param
        try:
            self.tsai.public_params_from_dict(self.KGC_pk_repo[self.KGC_id])
            self._dbg("Loaded KGC param local repo")
        except Exception as e:
            self._exit_err(f"Fail to init crypto with public params : {e}")

        # Step 5.a : Try to load our keys from file
        try:
            with open(f"{self.ID_h}/public.key", "r") as f:
                public_key = json.load(f)
            with open(f"{self.ID_h}/private.key", "r") as f:
                private_key = json.load(f)
            self._dbg("Read keys from local files")

        # Step 5.b : if files not exist, register to KGC
        except FileNotFoundError:
            self._dbg("Could not read keys from files, registering to KGC")
            res = requests.post(f"{self.KGC_server_url}/register", json={"user_id": self.mmsi})
            if res.status_code == 200:
                partial_key = json.loads(res.content)
                # Generate the private/public keys
                public_key, private_key = self.tsai.generate_keys(partial_key["sid"], partial_key["Rid"])
                # Save them to local files
                with open(f"{self.ID_h}/public.key", "w") as f:
                    json.dump(public_key, f)
                with open(f"{self.ID_h}/private.key", "w") as f:
                    json.dump(private_key, f)
                # Finally, send our public key to the server
                res = requests.post(f"{self.KGC_server_url}/send-pk", json={"user_id": self.mmsi, "public_key": public_key})

                if res.status_code != 200:
                    self._exit_err(f"Fail to upload public key to KGC : {res.content.decode()}")
                self._dbg("Registration ok")
        
        except Exception as e:
            self._exit_err(f"Fail to load keys from file : {e}")
        
        # Step 6 : Setup our cryptosystem with our keys (could be done only in 5.a since generate keys does it automatically)
        try:
            self.tsai.set_keys(private_key, public_key)
            self.public_key = public_key
        except Exception as e:
            self._exit_err(f"Fail to set crypto user keys : {e}")

        # Step 7 : If we want to flag the unauth msgs, run the thread
        if self.verify and self.retransmit and self.flag_unauth:
            threading.Thread(target=self._garbage_collector_thread, daemon=True)

        # We're done !
        
    def setupZMQ(self):
        '''
        Setup the ZMQ sockets and subscribe to our topic
        '''
        context = zmq.Context()
        self.push_sock = context.socket(zmq.PUSH)
        self.sub_sock = context.socket(zmq.SUB)
        self.push_sock.connect(f"tcp://localhost:{4001}")
        self.sub_sock.connect(f"tcp://localhost:{4000}")

        msg = b""
        while msg != b"OK":
            # Chose a 4 bytes ID
            self.topic = random.randbytes(4)
            self._dbg(f"Chose topic {self.topic}")
            # Subscribe to our topic
            self.sub_sock.subscribe(self.topic)
            time.sleep(0.1)
            self.push_sock.send_multipart([self.topic, b"CONNECT"]) # Send connect request to ZMQ server
            _, msg = self.sub_sock.recv_multipart()
            if msg == b"OK":
                self._dbg("Connection OK to ZMQ server")
            else:
                self._err("Fail to connect to ZMQ server")



    def update_repos(self):
        '''
        Fetch the three repos from LO server
        '''
        try:
            # User public keys
            res = requests.get(f"{self.LO_url}/user-pk-repo")
            if res.status_code == 200:
                data = json.loads(res.content.decode())
                self.public_key_repo = data
                ## TODO Add verification that slef.public_key == self.public_key_repo[self.ID]
            else:
                self._err("Error while fetching user pk repo from LO")

            # KGC public keys
            res = requests.get(f"{self.LO_url}/KGC-pk-repo")
            if res.status_code == 200:
                data = json.loads(res.content.decode())
                self.KGC_pk_repo = data
            else:
                self._err("Error while fetching KGC pk repo from LO")

            # user KGC repo
            res = requests.get(f"{self.LO_url}/user-KGC-repo")
            if res.status_code == 200:
                data = json.loads(res.content.decode())
                self.user_KGC_repo = data
                ## TODO Add verification that slef.KGC_id == self.user_kgc_repo[self.ID]
            else:
                self._err("Error while fetching user KGC repo from LO")
        except Exception as e:
            self._err(f"Error while updating repos: {e}")
        

    def save_repos(self):
        '''
        Save the 3 repos to the <ID_h> folder
        '''
        with open(f"{self.ID_h}/public-key-repo", "w") as f:
            json.dump(self.public_key_repo, f)
        with open(f"{self.ID_h}/user-kgc-repo", "w") as f:
            json.dump(self.user_KGC_repo, f)
        with open(f"{self.ID_h}/KGC-pk-repo", "w") as f:
            json.dump(self.KGC_pk_repo, f)

    def load_repos(self):
        '''
        Try to load repos from <ID_h> folder
        '''
        with open(f"{self.ID_h}/public-key-repo", "w") as f:
            self.public_key_repo = json.load(f)
        with open(f"{self.ID_h}/user-kgc-repo", "w") as f:
            self.user_KGC_repo = json.load(f)
        with open(f"{self.ID_h}/KGC-pk-repo", "w") as f:
            self.KGC_pk_repo = json.load(f)

    def send_dict(self, d):
        """
        Send a message from a dict, either via ZMQ or the SDR
        """
        if self.simulate:
            messages = pyais.encode_dict(d)
            for m in messages:
                self.push_sock.send_multipart([self.topic, m.encode("ascii")])
        else:
            self.aiserial.send_phrase(d)
    
    def send_bytes(self, s):
        """
        Send a message from a phrase
        """
        if self.simulate:
            self.push_sock.send_multipart([self.topic, s])
        else:
            data = pyais.decode(s).asdict()
            self.aiserial.send_phrase(data)
        
    def send_message(self, message: bytes):
        self._dbg(f"Sending {message}")
        msg_type = pyais.decode(message).asdict()["msg_type"]
        # if we need to authenticate, and either it's a type 1 msg that needs auth or another message type
        if self.auth and ((self.not_signed >= self.sign_every and msg_type == 1) or msg_type != 1) :
            # reset not signed
            self.not_signed = 0
            # First send the message
            self.send_bytes(message)
            
            # Then we need to sign the message
            timestamp = int(time.time()).to_bytes(4, 'little') # 32bits timestamp
            signature = self.tsai.sign(sha256(message[6:-2]+timestamp).digest()) # Sign sha256(msg|timestamp), we remove first 6 and 2 last (checksum) chars from msg cause when sending its !AIVDO and when receiving its !AIVDM so msg id will change 
            self._dbg(f"Signing {message} with id {sha256(message[6:-2]).digest()[:4]}")
            signature_msg = signature+timestamp+sha256(message[6:-2]).digest()[:4] # Send sign|timestamp|msg_id, we remove first 6 and 2 last (checksum) chars from msg cause when sending its !AIVDO and when receiving its !AIVDM so msg id will change 
            ais_signature = self.send_dict({'msg_type': 8, "mmsi": int(self.mmsi), "data": signature_msg, "dac": 100, "fid": 0})
            return
        # If we send an unsigned message and it's type one
        elif self.auth and self.not_signed < self.sign_every and msg_type == 1:
            self.not_signed += 1

        self.send_bytes(message)

    def ask_public_key(self, target):
        """
        Send message 6 with dac = 100 and fid = 1
        """
        data = {
            "type": 6,
            "mmsi": self.mmsi,
            "dest_mmsi": target,
            "dac": 100,
            "fid": 1,
            "data": b"\x00"
        }
        self.send_dict(msg_ais)

    def send_public_key(self):
        """
        Send two message 8, with dac = 100 and fid = 2 for Pid and dac = 100, fid = 3 for Rid
        """
        data = {
            "type": 8,
            "mmsi": self.mmsi,
            "dac": 100,
            "fid": 2,
            "data": bytes.fromhex(self.public_key['Pid']),
        }
        self.send_dict(data)
        data = {
            "type": 8,
            "mmsi": self.mmsi,
            "dac": 100,
            "fid": 3,
            "data": bytes.fromhex(self.public_key['Rid']),
        }
        self.send_dict(data)

    def accept_msg(self, message):
        mmsi = pyais.decode(message).asdict()["mmsi"]
        logger.log(f"[{self.mmsi}]: Received signed message : {message} from {mmsi}", logger.SUCCESS)
        if self.retransmit:
            self.aiserial.retransmit(message)
    def reject_msg(self, message):
        mmsi = pyais.decode(message).asdict()["mmsi"]
        logger.log(f"[{self.mmsi}]: Received UNsigned message : {message} from {mmsi}", logger.FAIL)

    def receive_thread(self):
        """
        While true loop to receive and verify messages
        """
        self._dbg("Starting recv thread")
        while True:
            if self.simulate:
                _, msg = self.sub_sock.recv_multipart()
            else:
                msg = self.aiserial.receive_phrase()

            msg = msg.strip()
            self._dbg(msg)

            if self.verify:
                try:
                    decoded = pyais.decode(msg).asdict()
                except Exception as e:
                    if "Missing fragment" not in str(e):
                        print(f"[{self.mmsi}]: Failed to decode AIS msg {msg}. Error : {e}")
                        continue # If fail, go back to the while loop
                    else:
                        # If its a multipart msg
                        self.fragment_buffer.append(msg)
                        try: 
                            # Try to decode multipart
                            decoded = pyais.decode(*self.fragment_buffer).asdict()
                            # If success, empty partial buffer
                            self.fragment_buffer = []
                        except:
                            continue
                # If its a type one, automatically accept if authenticated
                if decoded["msg_type"] == 1 and self._is_auth(decoded["mmsi"]):
                    self.accept_msg(msg) # If it's the case we accept the message. Later in the thread it will be stored in the buffer and if it's signed it will be accepted twice. Not a big deal

                # If its a signature
                if decoded['msg_type'] == 8 and decoded['dac'] == 100 and decoded['fid'] == 0:
                    recv_timestamp = int(time.time())
                    signature = bytearray(decoded["data"])[0:65] #  sign|timestamp|id
                    timestamp_b = bytearray(decoded["data"])[65:69] # 4 bytes timestamp (32bits)
                    timestamp = int.from_bytes(timestamp_b, 'little')
                    id_sender_str = str(decoded["mmsi"])
                    id_sender_bytes = id_sender_str.encode("ascii")

                    msg_id = int.from_bytes(bytearray(decoded["data"])[69:]+id_sender_bytes, 'little')
                    
                    # Try to retreive msg from buffer
                    if msg_id in self.buffer:
                        
                        # Check replay attack
                        if timestamp <= recv_timestamp and recv_timestamp - timestamp < self.time_threshold:
                            # If we don't have the public key, ask for it
                            if id_sender_str not in self.public_key_repo:
                                self.ask_public_key(decoded["mmsi"])
                                continue

                            # Get message hash to verify and remove it from buffer
                            msg_bytes = self.buffer.pop(msg_id)["msg"]
                            msg_h = sha256(msg_bytes[6:-2]+timestamp_b).digest()
                            
                            # Init tsai with public KGC master key 
                            self.tsai_verify.public_params_from_dict(self.KGC_pk_repo[self.user_KGC_repo[id_sender_str]])
                            # Verify using repospublic key
                            if self.tsai_verify.verify(msg_h, signature, id_sender_bytes, self.public_key_repo[id_sender_str]):
                                # If we got an auth message 1, auth the mmsi for 5 minutes
                                if pyais.decode(msg_bytes).asdict()["msg_type"] == 1:
                                    self.authenticated[pyais.decode(msg_bytes).asdict()["mmsi"]] = time.time()
                                self.accept_msg(msg_bytes)
                            else:
                                self.reject_msg(msg_bytes)
                    else:
                        self._dbg(f"sha256 of signature : {bytearray(decoded['data'])[69:]}")
                        self._dbg(f"id sender bytes of signature : {id_sender_bytes}")
                        self._info(f"Got sign without msg : id was {msg_id}")

                # If it's a public key request send the public key. It does not need to be signed !
                elif decoded['msg_type'] == 6 and decoded['dac'] == 100 and decoded['fid'] == 1 and str(decoded["dest_mmsi"]) == self.mmsi:
                    self.send_public_key()

                # If it's a public key Pid we don't have yet
                elif decoded["msg_type"] == 8 and decoded["dac"] == 100 and decoded["fid"] == 2:
                    # If we don't have public key or Pid
                    mmsi_str = str(decoded["mmsi"])
                    if mmsi_str not in self.public_key_repo:
                        self.public_key_repo[mmsi_str] = {}
                    if "Pid" not in self.public_key_repo[mmsi_str]:
                        self.public_key_repo[mmsi_str]["Pid"] = decoded["data"].hex()

                # If it's a public key Rid we don't have yet
                elif decoded["msg_type"] == 8 and decoded["dac"] == 100 and decoded["fid"] == 3:
                    # If we don't have public key or Pid
                    mmsi_str = str(decoded["mmsi"])
                    if mmsi_str not in self.public_key_repo:
                        self.public_key_repo[mmsi_str] = {}
                    if "Rid" not in self.public_key_repo[mmsi_str]:
                        self.public_key_repo[mmsi_str]["Rid"] = decoded["data"].hex()

                # If its a normal message
                else:
                    try:
                        id_sender_bytes = str(pyais.decode(msg).asdict()["mmsi"]).encode('ascii')
                        self._dbg(f"id sender byte : {id_sender_bytes}")
                        self._dbg(f"sha256 : {sha256(msg[6:-2]).digest()[:4]}")
                        msg_id = int.from_bytes(sha256(msg[6:-2]).digest()[:4]+id_sender_bytes, 'little') # Remove the first 6 chars cause when sending its !AIVDO and when receiving its !AIVDM, so id will change
                        self._dbg(f"Putting {msg} in {msg_id}")
                        self.buffer[msg_id] = {"msg":msg, "time": int(time.time())}
                    except:
                        continue
            else:
                if self.retransmit:
                    self.aiserial.retransmit(msg)
                print(f"[{self.mmsi}] recv msg : {msg}")

    def start_recv_thread(self):
        threading.Thread(target=self.receive_thread, daemon=True).start()

    def __del__(self):
        self._info("Exiting")
        if self.cleanup:
            self.cleanup()
    def cleanup(self):
        try:
            shutil.rmtree(self.ID_h)
        except Exception as e:
            self._exit_err(f"Fail cleanup: {e}")