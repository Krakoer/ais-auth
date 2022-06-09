from client import Client
from KGC import KGC
from authority import Authority
import time

if __name__ == "__main__":
    debug = True
    authority_url = "http://92.222.82.236:6000"
    # Setup LO
    authority = Authority(6000, url="0.0.0.0")
    authority.run_server()
    time.sleep(0.5)
    # Setup two KGC
    KGC1 = KGC("KGC_CANADA", 5000, authority_url, host="0.0.0.0", debug=debug)
    KGC2 = KGC("KGC_USA", 5001, authority_url, host="0.0.0.0", debug=debug)

    KGC1.setup()
    KGC2.setup()
  
    KGC1.run_server()
    KGC2.run_server()

    while True:
        time.sleep(0.5)
