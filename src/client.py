import requests
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

class Client:
    def __init__(self, ID, param_path, KGC_url_dict, KGC_id, auth=True, verify=True, simulate = True):
        self.ID = ID
        self.ID_h = sha256(self.ID.encode("ascii")).hexdigest()

        self.buffer = {} # Buffer for msg
        self.partial_buffer = [] # Buffer for multipart msg

        self.KGC_url_dict = KGC_url_dict
        self.KGC_server_url = KGC_url_dict[KGC_id]
        self.KGC_id = KGC_id
        self.KGC_id_h = sha256(KGC_id.encode("ascii")).hexdigest()
        
        self.tsai = TsaiUser(param_path)
        self.tsai_verify = TsaiUser(param_path)

        self.time_threshold = 30 # Number of seconds to detect replay attack

        ## For now, repos are manually setup !
        self.public_key_repo = {
            "888888888": {"Pid": "0355D6C5AA84F2B74984CEAD57F1E90CFF4CF67BDEC91A74B1C7444E678B139C72E762D4AC2135943C1D9BE1940A6CF17902DFF45033ABA094AC180C5812628204", "Rid": "029D8EC6185A26E403BEA13AC5C8EAEAAB1E9C62C8D54C5158DAE0891E6FB0D30EBFB8E0FE5CB4A832D0A315481F5BBA49EB87E8BB887106CD762AA823AFFD8FEA"},
            "444444444": {"Pid": "0203F7B2AED023F3B24A35DF9A17A57E3B9A28F18EB3F74759EA144E8E0B14D31EAB665F0CF43B52603154BE0AEB69469D2DEFB0C01F6D4ED4E6C710DDE4CC73E6", "Rid": "0222F12A45BD9723E74B7248C0E2775A6627C426E953D22140D971706C2BE053541D27A8B8D1AFA9AA1C8DE28B06779B4F0B7F6DE2B06E42C0CC52FDA4F120F84A"},
        } # Keys : MMSIs, values : public keys
        self.KGC_repo = {
            "888888888": "KGC1",
            "444444444": "KGC2",
        } # Keys : MMSIs, values : KGC id

        self.auth = auth
        self.verify = verify
        self.simulate = simulate
        # Setup ZMQ
        if self.simulate:
            self.setupZMQ()

        

    def setupZMQ(self):
        self.id = int(self.ID_h[:3], 16)
        self.topic = f"{self.id:04d}".encode("ascii")
        context = zmq.Context()
        self.push_sock = context.socket(zmq.PUSH)
        self.sub_sock = context.socket(zmq.SUB)
        self.push_sock.connect(f"tcp://localhost:{4001}")
        self.sub_sock.connect(f"tcp://localhost:{4000}")
        # if self.id == 2992: self.sub_sock.subscribe(f"{1675:04d}".encode("ascii"))
        # if self.id == 1675: self.sub_sock.subscribe(f"{2992:04d}".encode("ascii"))
        for i in range(4096):
            if i != self.id:
                if i == 2992 or i == 1675:
                    self.sub_sock.subscribe(f"{i:04d}".encode("ascii"))
        
    def setup_crypto(self):
        ## First, create our folder to store our keys and public params for all KGC's
        try:
            os.mkdir(self.ID_h)
        except FileExistsError:
            pass
        

        ## First, get or update the public parameters for all KGC:
        public_params_have_changed = False # Check if our public params have changed
        ## TODO : only check for changed for our server. Otherwise, just overwrite with server response
        for kgc_id, kgc_url in self.KGC_url_dict.items():
            kgc_id_h = sha256(kgc_id.encode("ascii")).hexdigest()
            try:
                with open(f"{self.ID_h}/{kgc_id_h}_params.txt", 'r') as f:
                    P_stored = json.load(f)["P"]
                # Compare online params with stored ones
                res = requests.get(f"{kgc_url}/params")
                server_params = json.loads(res.content)
                P_server = server_params["P"]
                
                # If they differ, update them
                if P_server != P_stored:
                    if kgc_id == self.KGC_id: # If its our server, keep track of the change to re-generate our keys later
                        public_params_have_changed = True
                    # print(f"[{self.ID}]: updating public params")
                    with open(f"{self.ID_h}/{kgc_id_h}_params.txt", 'w') as f:
                        json.dump(server_params, f)

            except FileNotFoundError:
                if kgc_id == self.KGC_id:
                    public_params_have_changed = True
                # If the public params are unknown, get them
                res = requests.get(f"{kgc_url}/params")
                server_params = json.loads(res.content)
                with open(f"{self.ID_h}/{kgc_id_h}_params.txt", 'w') as f:
                    json.dump(server_params, f)

            except Exception as e:
                print(f"[{self.ID}]: Problem getting public parameters {e}. Exiting")
                exit(1)
        
        # When public params are up to date, init crypto system with them
        with open(f"{self.ID_h}/{self.KGC_id_h}_params.txt", 'r') as f:
            pp = json.load(f)
            self.tsai.public_params_from_dict(pp)

        print(f"[{self.ID}]: Setting public params OK")

        # If public params have changed, regenerate public and private key
        if(public_params_have_changed):
            # Get partial private key
            res = requests.get(f"{self.KGC_server_url}/register/{self.ID}")
            partial_key = json.loads(res.content)
            # Generate the private/public keys
            public_key, private_key = self.tsai.generate_keys(partial_key["sid"], partial_key["Rid"])

            print(f"[{self.ID}]: Get full private/public keys : OK")
            
            # Save all that in file
            with open(f"{self.ID_h}/private.key", 'w') as f:
                json.dump(private_key, f)
            with open(f"{self.ID_h}/public.key", 'w') as f:
                json.dump(public_key, f)
        
        # If public params have not changed
        else:
            # Try to read public and private keys from files
            try:
                with open(f"{self.ID_h}/private.key", 'r') as private, open(f"{self.ID_h}/public.key", 'r') as public:
                    private_key = json.load(private)
                    public_key = json.load(public)

                # Init the crypto with that
                self.tsai.set_keys(private_key, public_key)
            except Exception as e:
                print(f"[{self.ID}]: Error while reading keys from file : {e}")
                exit(1)

    def send(self, message: bytes):
        if self.simulate:
            if self.auth:
                # First send the message
                msg = message
                self.push_sock.send_multipart([self.topic, msg])
                
                # Then we need to sign the message
                timestamp = int(time.time()).to_bytes(4, 'little') # 32bits timestamp
                signature = self.tsai.sign(sha256(message+timestamp).digest()) # Sign sha256(msg|timestamp)

                signature_msg = signature+timestamp+sha256(message).digest()[:4] # Send sign|timestamp|msg_id
                ais_signature = pyais.encode_dict({'type': 8, "mmsi": int(self.ID), "data": signature_msg})
                for m in ais_signature:
                    print(f"[{self.ID}]: sent \t{m}")
                    self.push_sock.send_multipart([self.topic, m.encode('ascii')])
                
            else:
                self.push_sock.send_multipart([self.topic, message])

    def get_kgc_params(self, kgc_id):
        """
        try to fetch sha256(id)_params.txt as json
        returns dict
        """
        if type(kgc_id) == str:
            kgc_id = kgc_id.encode("ascii")
        h = sha256(kgc_id).hexdigest()
        with open(f"{self.ID_h}/{h}_params.txt", 'r') as f:
            params = json.load(f)
        return params

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
                            self.partial_buffer.append(msg)
                            print(f"[{self.ID}]: received \t{msg}")
                            try: 
                                # Try to decode multipart
                                decoded = pyais.decode(*self.partial_buffer).asdict()
                                # If success, empty partial buffer
                                self.partial_buffer = []
                            except:
                                continue


                    # If its a signature
                    if decoded['msg_type'] == 8 and decoded['dac'] == 0 and decoded['fid'] == 0:
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
                                # Get message hash to verify and remove it from buffer
                                msg_bytes = self.buffer.pop(msg_id)
                                msg_h = sha256(msg_bytes+timestamp_b).digest()
                                
                                # Init tsai with public KGC master key 
                                self.tsai_verify.public_params_from_dict(self.get_kgc_params(self.KGC_repo[id_sender_str]))
                                # Verify using repospublic key
                                if self.tsai_verify.verify(msg_h, signature, id_sender_bytes, self.public_key_repo[id_sender_str]):
                                    logger.log(f"[{self.ID}]: Received signed message : {msg_bytes} from {id_sender_str}", logger.SUCCESS)
                                else:
                                    logger.log(f"[{self.ID}]: Received UNsigned message : {msg_bytes} from {id_sender_str}", logger.FAIL)
                        else:
                            print(f"[{self.ID}]: Got sign without msg")

                    # If its a normal message
                    else:
                        id_sender_bytes = str(pyais.decode(msg).asdict()["mmsi"]).encode('ascii')
                        msg_id = int.from_bytes(sha256(msg).digest()[:4]+id_sender_bytes, 'little')
                        self.buffer[msg_id] = msg
                else:
                    print(f"[{self.ID}] recv msg : {msg}")

    def start_recv_thread(self):
        threading.Thread(target=self.receive_thread).start()

    def __del__(self):
        print(f"{[self.ID]}: Exiting...")
        # self.clean()

    def clean(self):
        try:
            shutil.rmtree(self.ID_h)
        except Exception as e:
            print(e)