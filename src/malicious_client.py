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

class EvilClient:
    def __init__(self, ID, KGC_url, KGC_id, LO_url, target, auth=True, verify=True, simulate = True, param_path="a.param", debug=False, cleanup=False):
        self.ID = ID
        self.ID_h = sha256(self.ID.encode("ascii")).hexdigest()

        self.target = target

        self.buffer = {} # Buffer for msg to verify
        self.fragment_buffer = [] # Buffer for multipart msg

        self.KGC_server_url = KGC_url
        self.KGC_id = KGC_id
        self.KGC_id_h = sha256(KGC_id.encode("ascii")).hexdigest()
        self.LO_url = LO_url
        
        self.tsai = TsaiUser(param_path)
        self.tsai_verify = TsaiUser(param_path)
        self.public_key = {} 

        self.time_threshold = 30 # Number of seconds to detect replay attack

        self.public_key_repo = {} # Keys : MMSIs, values : public keys
        self.user_KGC_repo = {} # Keys : MMSIs, values : KGC id
        self.KGC_pk_repo = {} # Keys : KGC_id, value : KGC public param

        self.auth = auth
        self.verify = verify
        self.simulate = simulate

        self.debug = debug

    def _exit_err(self, err):
        logger.log(f"[{self.ID}]: {err}. ABORTING", logger.FAIL)
        exit(1)
    def _err(self, err):
        logger.log(f"[{self.ID}]: {err}", logger.FAIL)
    def _info(self, msg):
        logger.log(f"[{self.ID}]: {msg}", logger.INFO)
    def _dbg(self, msg):
        if self.debug:
            self._info(msg)

    def setup(self):
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
            res = requests.post(f"{self.KGC_server_url}/register", json={"user_id": self.ID})
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
                res = requests.post(f"{self.KGC_server_url}/send-pk", json={"user_id": self.ID, "public_key": public_key})

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

        # We're done !
        
    def setupZMQ(self):
        '''
        Setup the ZMQ sockets and subscribe to all topic except ours
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
            # Subscribe to our channel
            self.sub_sock.subscribe(self.topic)
            time.sleep(0.1) 
            self.push_sock.send_multipart([self.topic, b"CONNECT"])
            _, msg = self.sub_sock.recv_multipart()
            self._dbg(f"Received {msg} back from server")



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

    def send(self, message):
        if self.simulate:
            self.push_sock.send_multipart([self.topic, message])
        
    def send_message(self, message: bytes):
        if self.auth:
            # First send the message
            msg = message
            self.send(msg)
            # Then we need to sign the message
            timestamp = int(time.time()).to_bytes(4, 'little') # 32bits timestamp
            signature = self.tsai.sign(sha256(message+timestamp).digest()) # Sign sha256(msg|timestamp)

            signature_msg = signature+timestamp+sha256(message).digest()[:4] # Send sign|timestamp|msg_id
            ais_signature = pyais.encode_dict({'type': 8, "mmsi": int(self.target), "data": signature_msg, "dac": 100, "fid": 0})
            for m in ais_signature:
                self.send(m.encode('ascii'))
            
        else:
            self.send(message)

    def ask_public_key(self, target):
        data = {
            "type": 6,
            "mmsi": self.ID,
            "dest_mmsi": target,
            "dac": 100,
            "fid": 1,
            "data": b"\x00" # Must be here else pyais panics and create a big payload 
        }
        msg_ais = pyais.encode_dict(data)[0].encode('ascii')
        self.send(msg_ais)

    def send_public_key(self):
        # Send Pid the Rid
        data = {
            "type": 8,
            "mmsi": self.target,
            "dac": 100,
            "fid": 2,
            "data": bytes.fromhex(self.public_key['Pid']),
        }
        msgs_ais = pyais.encode_dict(data)
        for m in msgs_ais:
            self.send(m.encode("ascii"))
        data = {
            "type": 8,
            "mmsi": self.target,
            "dac": 100,
            "fid": 3,
            "data": bytes.fromhex(self.public_key['Rid']),
        }
        msgs_ais = pyais.encode_dict(data)
        for m in msgs_ais:
            self.send(m.encode("ascii"))

    def receive_thread(self):
        if self.simulate:
            while True:
                _, msg = self.sub_sock.recv_multipart()
                if self.verify:
                    # Get MMSI from message
                    try:
                        decoded = pyais.decode(msg).asdict()
                    except Exception as e:
                        if "Missing fragment" not in str(e):
                            print(f"[{self.ID}]: Failed to decode AIS msg {msg}. Error : {e}")
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
                                msg_bytes = self.buffer.pop(msg_id)
                                msg_h = sha256(msg_bytes+timestamp_b).digest()
                                
                                # Init tsai with public KGC master key 
                                self.tsai_verify.public_params_from_dict(self.KGC_pk_repo[self.user_KGC_repo[id_sender_str]])
                                # Verify using repospublic key
                                if self.tsai_verify.verify(msg_h, signature, id_sender_bytes, self.public_key_repo[id_sender_str]):
                                    logger.log(f"[{self.ID}]: Received signed message : {msg_bytes} from {id_sender_str}", logger.SUCCESS)
                                else:
                                    logger.log(f"[{self.ID}]: Received UNsigned message : {msg_bytes} from {id_sender_str}", logger.FAIL)
                        else:
                            print(f"[{self.ID}]: Got sign without msg")

                    # If it's a public key request send the public key. It does not need to be signed !
                    # We're malicious so we're going to send our public key AHAHAHAHA
                    elif decoded['msg_type'] == 6 and decoded['dac'] == 100 and decoded['fid'] == 1 and str(decoded["dest_mmsi"]) == self.target:
                        self.send_public_key()

                    # If it's a public key Pid we don't have yet
                    elif decoded["msg_type"] == 8 and decoded["dac"] == 100 and decoded["fid"] == 2:
                        # If we don't have public key or Pid
                        mmsi_str = str(decoded["mmsi"])
                        if mmsi_str not in self.public_key_repo:
                            self.public_key_repo[mmsi_str] = {}
                        if "Pid" not in self.public_key_repo[mmsi_str]:
                            self.public_key_repo[mmsi_str]["Pid"] = decoded["data"].hex()

                    # If it's a public key Pid we don't have yet
                    elif decoded["msg_type"] == 8 and decoded["dac"] == 100 and decoded["fid"] == 3:
                        # If we don't have public key or Pid
                        mmsi_str = str(decoded["mmsi"])
                        if mmsi_str not in self.public_key_repo:
                            self.public_key_repo[mmsi_str] = {}
                        if "Rid" not in self.public_key_repo[mmsi_str]:
                            self.public_key_repo[mmsi_str]["Rid"] = decoded["data"].hex()

                    # If its a normal message
                    else:
                        id_sender_bytes = str(pyais.decode(msg).asdict()["mmsi"]).encode('ascii')
                        msg_id = int.from_bytes(sha256(msg).digest()[:4]+id_sender_bytes, 'little')
                        self.buffer[msg_id] = msg
                else:
                    print(f"[{self.ID}] recv msg : {msg}")

    def start_recv_thread(self):
        threading.Thread(target=self.receive_thread, daemon=True).start()

    def __del__(self):
        self._dbg("Exiting")
        if self.cleanup:
            self.cleanup()
    def cleanup(self):
        try:
            shutil.rmtree(self.ID_h)
        except Exception as e:
            self._exit_err(f"Fail cleanup: {e}")