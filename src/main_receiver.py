from client import Client
import time

if __name__=="__main__":
    debug = True
    KGC_url = "http://92.222.82.236:5001"
    auhtority_url = "http://92.222.82.236:6000"

    mmsi = 338427627
    client = Client(mmsi, KGC_url, "KGC_USA", auhtority_url, simulate=False, debug=debug, cleanup=True, retransmit=True)

    client.setup()
    client.update_repos()
    time.sleep(1)

    client.start_recv_thread()

    while True:
        time.sleep(0.5)