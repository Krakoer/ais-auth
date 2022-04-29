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
from minilogger import *

class Client:
    def __init__(self, ID, param_path, KGC_url_dict, KGC_id, auth=True, verify=True, simulate = True):
        self.ID = ID
        self.ID_h = sha256(self.ID.encode("ascii")).hexdigest()

        self.buffer = {}

        self.KGC_url_dict = KGC_url_dict
        self.KGC_server_url = KGC_url_dict[KGC_id]
        self.KGC_id = KGC_id
        self.KGC_id_h = sha256(KGC_id.encode("ascii")).hexdigest()
        
        self.tsai = TsaiUser(param_path)
        self.tsai_verify = TsaiUser(param_path)


        ## For now, repos are manually setup !
        self.public_key_repo = {
            "888888888": {"Pid": "0308E7B3616335E365487E4A4682AC0B4D275BB33AD58ABC55FA992645D3EF914F7EC48DEB3B6D56E991B351350C4A0C98BBCF196C7000EAFCBF6505BF22807F7C", "Rid": "0252D7B4D39B6F3F9E2EFC639117C55F7EA69E3867800A6A7E1083B099E3B77A310143500C012AC5BC018AD88652ED4848C3DB309986C147F21ABD62597D56E03A"},
            "444444444": {"Pid": "022A17F08B0782E8B3AF04A35022DF4D0323EE9EAD238CF4E6858EF11D2CC28147D221BA9E36811F60435B4F3B6C25AB692E8039FFBC47EDF583FEAAD7620EB970", "Rid": "0351D6CBB881239EC266DED4285669AE57515C77BE85F535A37D470C1B8E8BC5CB91069DE2B67CFDC3D1F4EA8920BEEBE9702D0F187E49CC878F3A1EF0A4E21A39"},
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
                signature = self.tsai.sign(sha256(message).digest())

                msg = self.ID.encode("ascii")+b"::"+message+b"::"+signature
                self.push_sock.send_multipart([self.topic, msg])
                
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
                    #Split msg
                    id_sender_bytes = msg.split(b"::")[0]
                    id_sender_str = id_sender_bytes.decode()
                    msg_string = msg.split(b"::")[1].decode()
                    msg_h =sha256(msg.split(b"::")[1]).digest()
                    signature = bytearray(msg.split(b"::")[2])
                    signature[1] += 1
                    # Init tsai with public KGC master key 
                    self.tsai_verify.public_params_from_dict(self.get_kgc_params(self.KGC_repo[id_sender_str]))
                    # Verify using repospublic key
                    if self.tsai_verify.verify(msg_h, signature, id_sender_bytes, self.public_key_repo[id_sender_str]):
                        logger.log(f"[{self.ID}]: Received signed message : {msg_string} from {id_sender_str}", logger.SUCCESS)
                    else:
                        logger.log(f"[{self.ID}]: Received UNsigned message : {msg_string} from {id_sender_str}", logger.FAIL)
                        
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