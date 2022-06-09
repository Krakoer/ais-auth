import time
import os
import json
from hashlib import sha256
from tsai import TsaiKGC
from bottle import route, run, abort, Bottle, request
from bottle import debug as bottle_dbg
import multiprocessing as mp
import shutil
from minilogger import *
import requests

class KGC:
    def __init__(self, ID, port, LO_url, debug=False, param_path="a.param", host="127.0.0.1"):
        self.ID = ID
        self.host=host
        self.port = port
        self.ID_h = sha256(ID.encode('ascii')).hexdigest()
        self.tsai = TsaiKGC(param_path)
        self.app = Bottle()
        self.LO_url = LO_url
        self._route() # From solution https://stackoverflow.com/a/16059246 to run multiple servers
        self.debug=debug
        bottle_dbg(debug)

    def _exit_err(self, err):
        logger.log(f"[{self.ID}]: {err}. ABORTING", logger.FAIL)
        exit(1)
    def _err(self, err):
        logger.log(f"[{self.ID}]: {err}", logger.FAIL)
    def _info(self, msg):
        logger.log(f"[{self.ID}]; {msg}", logger.INFO)

    def _route(self):
        self.app.route("/register", callback = self._register, method="POST")
        self.app.route("/send-pk", callback=self._reg_public_key, method="POST")

    def setup(self):
        try:
            os.mkdir(self.ID_h)
        except FileExistsError:
            pass

        # First, try to read public params and private key from file 
        try:
            with open(f"{self.ID_h}/params.txt", 'r') as f:
                public_params = json.load(f)
            self.tsai.set_public_params(public_params)

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
            self._exit_err(f"Failed to load/generate Master keys : {e}. ABORTING")

        # Send public key to LO for registration
        res = requests.post(f"{self.LO_url}/register-KGC", json={"KGC_id": self.ID, "public_key": public_params})
        if res.status_code == 200:
            if self.debug:
                self._info(f"Registration to LO successful")
        else:
            if self.debug:
                semf._err(f"Fail to register to LO : {res.content.decode()}")

    def _params(self):
        try:
            with open(f"{self.ID_h}/params.txt", 'r') as f:
                params = json.load(f)
            return params
        except e:
            self._err(f"Error while fetching public params : {e}")
            abort(404, "Error while fetching public params")

    def _reg_public_key(self):
        try:
            data = request.json
            user_id = data["user_id"]
            pk = data["public_key"]
            res = requests.post(f"{self.LO_url}/register-user", json={"user_id": user_id, "public_key": pk, "KGC_id": self.ID})
            if res.status_code == 200:
                return "Registration successful"
            else:
                abort(text="Error while registering")
        except Exception as e:
            abort(f"Fail to register : {e}")

    def _register(self):
        try:
            _id = request.json["user_id"]
            if type(_id) == str:
                _id = _id.encode("ascii")
            assert type(_id) == bytes, "id must be bytes for registration"
            keys = self.tsai.partial_keygen(_id)
            return keys
        except Exception as e:
            abort(404, f"Error while registering : {e}")
    
    def _run(self):
        self.app.run(host = self.host, port=self.port, quiet=not self.debug)

    def run_server(self):
        self.p = mp.Process(target=self._run, daemon=True)
        self.p.start()

    def stop(self):
        self.app.close()        
        self.p.kill()
        try:
            shutil.rmtree(self.ID_h)
        except:
            pass