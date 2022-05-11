import time
import os
import json
from hashlib import sha256
from bottle import route, run, abort, Bottle, request, response
import threading
import shutil

class Authority:
    def __init__(self, port, url = "127.0.0.1"):
        self.url = url
        self.port = port
        self.app = Bottle()
        self._route() # From solution https://stackoverflow.com/a/16059246 to run multiple servers
        self.KGC_public_key_repo = {}
        self.KGC_user_repo = {}
        self.user_public_key_repo = {}

    def _route(self):
        self.app.route("/user-pk-repo", callback=self._user_pk)
        self.app.route("/user-KGC-repo", callback=self._KGC_user)
        self.app.route("/KGC-pk-repo", callback=self._KGC_pk)
        self.app.route("/register-user", callback = self._reg_user, method="POST")
        self.app.route("/register-KGC", callback=self._reg_kgc, method="POST")
    
    def _reg_user(self):
        try:
            data = request.json
            user_id = data["user_id"]
            KGC_id = data["KGC_id"]
            publick_key = data["public_key"]
            self.KGC_user_repo[user_id] = KGC_id
            self.user_public_key_repo[user_id] = publick_key
            return "Registration successful"
            
        except Exception as e:
            abort(code=500, text=f"An error occured: {e}")

    def _reg_kgc(self):
        try:
            data = request.json
            KGC_id = data["KGC_id"]
            pk = data["public_key"]
            self.KGC_public_key_repo[KGC_id] = pk
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
        self.app.run(host = self.url, port=self.port)

    def run_server(self):
        threading.Thread(target=self._run).start()

if __name__ == "__main__":
    authority = Authority(1337)
    authority.run_server()