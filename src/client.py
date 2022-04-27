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


class Client:
    def __init__(self, ID, param_path, KGC_url_dict, KGC_id, auth=True, verify=True, simulate = True):
        self.ID = ID
        self.ID_h = sha256(self.ID.encode("ascii")).hexdigest()

        self.KGC_url_dict = KGC_url_dict
        self.KGC_server_url = KGC_url_dict[KGC_id]
        self.KGC_id = KGC_id
        self.KGC_id_h = sha256(KGC_id.encode("ascii")).hexdigest()
        
        self.tsai = TsaiUser(param_path)

        self.auth = auth
        self.verify = verify
        self.simulate = simulate

    def setup(self):
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
        pass


    def __del__(self):
        print(f"{[self.ID]}: Exiting...")
        # self.clean()
    def clean(self):
        try:
            shutil.rmtree(self.ID_h)
        except Exception as e:
            print(e)


#     def setup(self):
#         # Get public parameters
#         res = requests.get("http://127.0.0.1:5000/params")
#         res = json.loads(res.content)

#         # Store them in a file
#         with open("params.txt", 'w') as f:
#             for k, v in res.items():
#                 f.write(f"{k}:{v}\n")

#         print("Get public params : OK")
        
#         # Request register
#         res = requests.post("http://127.0.0.1:5000/register", json={"id": ID})
#         partial_key = json.loads(res.content)

#         print("Get partial private key : OK")
        
#         # Generate the private/public keys
#         res = subprocess.run(["./client", "setup"], capture_output=True, stdin=open("a.param"), text=True)
#         output = res.stdout.strip()
#         user_key = {}
#         for l in output.splitlines():
#             name = l.split(":")[0]
#             value = l.split(":")[1]
#             user_key[name] = value

#         print("Get full private/public keys : OK")
        
#         # Save all that in file
#         with open("private.key", 'w') as f:
#             f.write(f"xid:{user_key['xid']}\n")
#             f.write(f"sid:{partial_key['sid']}\n")
#         with open("public.key", 'w') as f:
#             f.write(f"Pid:{user_key['Pid']}\n")
#             f.write(f"Rid:{partial_key['Rid']}\n")

#         print("Saving keys : OK")
#         return user_key["Pid"], partial_key['Rid']

# def setup(ID : str):
#     # Get public parameters
#     res = requests.get("http://127.0.0.1:5000/params")
#     res = json.loads(res.content)

#     # Store them in a file
#     with open("params.txt", 'w') as f:
#         for k, v in res.items():
#             f.write(f"{k}:{v}\n")

#     print("Get public params : OK")
    
#     # Request register
#     res = requests.post("http://127.0.0.1:5000/register", json={"id": ID})
#     partial_key = json.loads(res.content)

#     print("Get partial private key : OK")
    
#     # Generate the private/public keys
#     res = subprocess.run(["./client", "setup"], capture_output=True, stdin=open("a.param"), text=True)
#     output = res.stdout.strip()
#     user_key = {}
#     for l in output.splitlines():
#         name = l.split(":")[0]
#         value = l.split(":")[1]
#         user_key[name] = value

#     print("Get full private/public keys : OK")
    
#     # Save all that in file
#     with open("private.key", 'w') as f:
#         f.write(f"xid:{user_key['xid']}\n")
#         f.write(f"sid:{partial_key['sid']}\n")
#     with open("public.key", 'w') as f:
#         f.write(f"Pid:{user_key['Pid']}\n")
#         f.write(f"Rid:{partial_key['Rid']}\n")

#     print("Saving keys : OK")
#     return user_key["Pid"], partial_key['Rid']

# def main():
#     context = zmq.Context()
#     Pid, Rid = setup(sys.argv[1])
#     if sys.argv[2] == "send":
#         # We want to sign this message
#         message = b"Coucou"
#         m = hashlib.sha256()
#         m.update(message)
#         res = subprocess.run(["./client", "sign", m.digest()], capture_output=True, text=True, stdin=open("a.param"))
#         signature = res.stdout.strip()

#         # Send message, signature and public key to other client
#         socket = context.socket(zmq.REQ)
#         socket.connect("tcp://localhost:5555")
#         socket.send(message)
#         r = socket.recv()
#         socket.send_string(signature)
#         r = socket.recv()
#         socket.send_string(sys.argv[1]) # Send ID
#         r = socket.recv()
#         socket.send_string(Pid)
#         r = socket.recv()
#         socket.send_string(Rid)
#         r = socket.recv()

#     elif sys.argv[2] == "recv":
#         socket = context.socket(zmq.REP)
#         socket.bind("tcp://*:5555")
#         #  Wait for message and signature and public key to arrive
#         message = socket.recv()
#         print(f"Message : {message}")
#         socket.send(b"")

#         signature = socket.recv()
#         socket.send(b"")
#         print(f"Signature : {signature}")

#         id_ = socket.recv()
#         socket.send(b"")
#         print(f"id : {id_}")

#         Rid_h = socket.recv()
#         socket.send(b"")
#         print(f"Rid : {Rid_h}")

#         Pid_h = socket.recv()
#         socket.send(b"")
#         print(f"Pid : {Pid_h}")

#         # Verify the message
#         # int verify(unsigned char *message, char *signature, unsigned char* id_h, char* Rid_b64, char* Pid_b64){
#         h = hashlib.sha256()
#         h.update(message)
#         message = h.digest()
#         h = hashlib.sha256()
#         h.update(id_)
#         id_ = h.digest()
#         subprocess.run(["./client", "verify", message, signature, id_, Rid_h, Pid_h], stdin = open("a.param"))


# if __name__ == "__main__":
#     if len(sys.argv) < 3:
#         print(f"Usage : {sys.argv[0]} ID [send/recv]")
#     main()