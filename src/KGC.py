import time
import os
import json
from hashlib import sha256
from tsai import TsaiKGC
from bottle import route, run, abort, Bottle
import threading
import shutil

class KGC:
    def __init__(self, ID, port):
        self.ID = ID
        self.port = port
        self.ID_h = sha256(ID.encode('ascii')).hexdigest()
        self.tsai = TsaiKGC("a.param")
        self.app = Bottle()
        self._route() # From solution https://stackoverflow.com/a/16059246 to run multiple servers

    def _route(self):
        self.app.route("/params", callback=self._params)
        self.app.route("/register/<_id>", callback = self._register)

    def setup(self):
        try:
            os.mkdir(self.ID_h)
        except FileExistsError:
            pass

        # First, try to read public params and private key from file 
        try:
            with open(f"{self.ID_h}/params.txt", 'r') as f:
                params = json.load(f)
            self.tsai.set_public_params(params)

            with open(f"{self.ID_h}/private.key", 'r') as f:
                key = json.load(f)
            self.tsai.set_private_key(key)

        except FileNotFoundError:
            # If not found, we generate them
            public_params, private_key = self.tsai.master_keygen()
            with open(f"{self.ID_h}/params.txt", 'w') as f:
                json.dump(public_params, f)

            with open(f"{self.ID_h}/private.key", 'w') as f:
                json.dump(private_key, f)

        except Exception as e:
            print(e)
            print(f"[{self.ID}]: Failed to load/generate Master keys. Exiting")
            exit(1)

    def _params(self):
        try:
            with open(f"{self.ID_h}/params.txt", 'r') as f:
                params = json.load(f)
            return params
        except e:
            print(f"[{self.ID}]: Error while fetching public params : {e}")
            abort(404, "Error while fetching public params")

    def _register(self, _id):
        print(f"[{self.ID}]: Registering {_id}")
        try:
            h = sha256(_id.encode('ascii')).digest()
            keys = self.tsai.partial_keygen(h)
            return keys
        except Exception as e:
            abort(404, f"Error while registering : {e}")
    
    def _run(self):
        self.app.run(host = "localhost", port=self.port)

    def run_server(self):
        threading.Thread(target=self._run).start()

    def clean(self):
        try:
            shutil.rmtree(self.ID_h)
        except Exception as e:
            print(e)

    def __del__(self):
        # self.clean()
        pass
