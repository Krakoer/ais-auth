import requests
import json
import sys
import subprocess
from hashlib import sha256
import zmq
from pyais.encode import encode_dict
import threading
import os
import shutil
from tsai import TsaiUser
import time

class Client:
    def __init__(self, ID, param_path, KGC_url_dict, KGC_id, auth=True, verify=False, simulate = True):
        self.ID = ID
        self.ID_h = sha256(self.ID.encode("ascii")).hexdigest()

        self.buffer = {}

        self.KGC_url_dict = KGC_url_dict
        self.KGC_server_url = KGC_url_dict[KGC_id]
        self.KGC_id = KGC_id
        self.KGC_id_h = sha256(KGC_id.encode("ascii")).hexdigest()
        
        self.tsai = TsaiUser(param_path)


        self.auth = auth
        self.verify = verify
        self.simulate = simulate
        # Setup ZMQ
        if self.simulate:
            self.setupZMQ()

        

    def setupZMQ(self):
        self.id = int(self.ID_h[:3], 16)
        print(f"{self.ID} has id {self.id}")
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
                    print(f"{self.ID} sub to {i:04d}".encode("ascii"))
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

    def send(self, message):
        if self.simulate:
            if self.auth:
                # First we need to sign the message 
                self.push_sock.send_multipart([self.topic, message])
                signature = self.tsai.sign(sha256(message).digest())
                self.push_sock.send_multipart([self.topic, signature])
            else:
                self.push_sock.send_multipart([self.topic, message])

    def receive_thread(self):
        if self.simulate:
            while True:
                _, string = self.sub_sock.recv_multipart()
                if self.verify:
                    e
                else:
                    print(f"[{self.ID}] recv msg : {string}")

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