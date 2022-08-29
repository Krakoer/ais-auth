import time
import os
import json
from hashlib import sha256
from bottle import route, run, abort, Bottle, request, response
import sys
import shutil
import multiprocessing as mp
from tsai import TsaiKGC

class Authority:
    """
    Class wich simulates the Leading Authority as a KGC
    """
    def __init__(self, port = 3000, url = "127.0.0.1"):
        self.url = url
        self.port = port
        self.app = Bottle()                 
        self._route()                       # From solution https://stackoverflow.com/a/16059246 to run multiple servers
        self.user_repo = {}                 # Store public keys of users
        self.revocation = {"revocated": []}                # Revocation repo
        self.repo_path = "./LO-files/"      # Local repo to store everything
        
        self.tsai = TsaiKGC("a.param")

        self.setup()

    def setup(self):
        try:
            os.mkdir(self.repo_path)
        except FileExistsError:
            pass

        # First, try to read public params and private key from file 
        try:
            with open(f"{self.repo_path}/params.txt", 'r') as f:
                public_params = json.load(f)
            self.tsai.set_public_params(public_params)

            with open(f"{self.repo_path}/private.key", 'r') as f:
                key = json.load(f)
            self.tsai.set_private_key(key)

        except FileNotFoundError:
            # If not found, we generate them
            public_params, private_key = self.tsai.master_keygen()
            with open(f"{self.repo_path}/params.txt", 'w') as f:
                json.dump(public_params, f)

            with open(f"{self.repo_path}/private.key", 'w') as f:
                json.dump(private_key, f)

        except Exception as e:
            self._exit_err(f"Failed to load/generate Master keys : {e}. ABORTING")

    def _route(self):
        self.app.route("/user-pk", callback=self._user_pk)                          # Get user pk
        self.app.route("/revocated", callback=self._revocated)                      # Get revocated pk
        self.app.route("/params", callback=self._params)                            # Get KGC params
        self.app.route("/register", callback = self._register, method="POST")       # Post register user
        self.app.route("/send-pk", callback = self._send_pk, method="POST")         # Post user pk once generated

    def _user_pk(self):
        return self.user_repo

    def _revocated(self):
        return self.revocation

    def _params(self):
        try:
            with open(f"{self.repo_path}/params.txt", 'r') as f:
                params = json.load(f)
            return params
        except e:
            self._err(f"Error while fetching public params : {e}")
            abort(404, "Error while fetching public params")
    
    def _register(self):
        """
        Callback for user registration
        """
        try:
            _id = request.json["user_id"]
            if type(_id) == str:
                _id = _id.encode("ascii")
            assert type(_id) == bytes, "id must be bytes for registration"
            keys = self.tsai.partial_keygen(_id)
            return keys
        except Exception as e:
            abort(404, f"Error while registering : {e}")

    def _send_pk(self):
        try:
            data = request.json
            user_id = data["user_id"]
            pk = data["public_key"]
            self.user_repo[user_id] = pk
            self.save_repos()
            return "Registration successful"
        except Exception as e:
            abort(f"Fail to register : {e}")

    def _run(self):
        self.app.run(host=self.url, port=self.port)

    def load_from_files(self):
        with open(self.repo_path+"user-pk", "r") as f:
            self.user_repo = json.load(f)
        with open(self.repo_path+"revocation", "r") as f:
            self.revocation = json.load(f)

    def save_repos(self):
        with open(self.repo_path+"user-pk", "w") as f:
            json.dump(self.user_repo, f)
        with open(self.repo_path+"revocation", "w") as f:
            json.dump(self.revocation, f)

    def run_server(self):
        try:
            os.mkdir(self.repo_path)
        except:
            pass
        try:
            self.load_from_files()
        except:
            pass
        self.p = mp.Process(target=self._run, daemon=True)
        self.p.start()

    def stop(self):
        self.app.close()        
        self.p.kill()
        try:
            shutil.rmtree(self.repo_path)
        except:
            pass

    def _exit_err(self, err):
        logger.log(f"[LO]: {err}. ABORTING", logger.FAIL)
        exit(1)
    def _err(self, err):
        logger.log(f"[LO]: {err}", logger.FAIL)
    def _info(self, msg):
        logger.log(f"[LO]: {msg}", logger.INFO)
    def _dbg(self, msg):
        if self.debug:
            self._info(msg)