import time
import os
import json
from hashlib import sha256
from bottle import route, run, abort, Bottle, request, response
import sys
import shutil
import multiprocessing as mp

class Authority:
    """
    Class wich simulates the Leading Authority
    """
    def __init__(self, port, url = "127.0.0.1"):
        self.url = url
        self.port = port
        self.app = Bottle()                 
        self._route()                       # From solution https://stackoverflow.com/a/16059246 to run multiple servers
        self.KGC_public_key_repo = {}       # Store public keys of KGCs
        self.KGC_user_repo = {}             # Store public keys of users
        self.user_public_key_repo = {}      # Store which user is registered to which KGC
        self.repo_path = "./LO-files/"      # Local repo

    def _route(self):
        self.app.route("/user-pk-repo", callback=self._user_pk)                     # Get user pk
        self.app.route("/user-KGC-repo", callback=self._KGC_user)                   # Get KGC pk
        self.app.route("/KGC-pk-repo", callback=self._KGC_pk)                       # Get KGC user
        self.app.route("/register-user", callback = self._reg_user, method="POST")  # Post register user
        self.app.route("/register-KGC", callback=self._reg_kgc, method="POST")      # Post register KGC
    
    def _reg_user(self):
        """
        Callback for user registration
        """
        try:
            data = request.json
            user_id = data["user_id"]
            KGC_id = data["KGC_id"]
            publick_key = data["public_key"]
            self.KGC_user_repo[user_id] = KGC_id
            self.user_public_key_repo[user_id] = publick_key
            self.save_repos()
            return "Registration successful"
            
        except Exception as e:
            abort(code=500, text=f"An error occured: {e}")

    def _reg_kgc(self):
        try:
            data = request.json
            KGC_id = data["KGC_id"]
            pk = data["public_key"]
            self.KGC_public_key_repo[KGC_id] = pk
            self.save_repos()
            return "Registration successful"
        except Exception as e:
            abort(text=f"Fail to registr KGC : {e}")

    def _user_pk(self):
        return self.user_public_key_repo

    def _KGC_user(self):
        return self.KGC_user_repo

    def _KGC_pk(self):
        return self.KGC_public_key_repo

    def _run(self):
        self.app.run(host=self.url, port=self.port, quiet=True)

    def load_from_files(self):
        with open(self.repo_path+"KGC-pk", "r") as f:
            self.KGC_public_key_repo = json.load(f)
        with open(self.repo_path+"user-pk", "r") as f:
            self.user_public_key_repo = json.load(f)
        with open(self.repo_path+"user-KGC", "r") as f:
            self.KGC_user_repo = json.load(f)

    def save_repos(self):
        with open(self.repo_path+"KGC-pk", "w") as f:
            json.dump(self.KGC_public_key_repo, f)
        with open(self.repo_path+"user-pk", "w") as f:
            json.dump(self.user_public_key_repo, f)
        with open(self.repo_path+"user-KGC", "w") as f:
            json.dump(self.KGC_user_repo, f)

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