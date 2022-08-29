from client import Client
from authority import Authority
import time

if __name__ == "__main__":
    debug = True
    # Setup LO
    authority = Authority(url="0.0.0.0")
    authority.run_server()
    time.sleep(0.5)

    while True:
        time.sleep(0.5)
