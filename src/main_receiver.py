from client import Client
import time

if __name__=="__main__":
    debug = True
    auhtority_url = "http://92.222.82.236:3000"

    mmsi = 338427627
    client = Client(mmsi, auhtority_url, simulate=False, debug=debug, cleanup=True, retransmit=True, flag_unauth=False)

    client.setup()
    client.update_repos()
    time.sleep(1)

    client.start_recv_thread()

    while True:
        time.sleep(0.5)