from client import Client
from KGC import KGC
from authority import Authority
import time

if __name__ == "__main__":
    debug = True
    authority_url = "http://92.222.82.236:3000"
    # Setup LO
    authority = Authority(url="0.0.0.0")
    authority.run_server()
    time.sleep(0.5)

    while True:
        time.sleep(0.5)
