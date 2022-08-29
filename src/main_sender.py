from client import Client
from authority import Authority
from zmqServer import ZMQserver
import time
import pyais
import matplotlib.pyplot as plt
import random

if __name__ == "__main__":
    debug = True
    auhtority_url = "http://92.222.82.236:3000"

    mmsi = 926724788
    client = Client(mmsi, auhtority_url, simulate=False, debug=debug, cleanup=True, retransmit=False, flag_unauth=False, dont_listen=True)

    client.setup()
    client.update_repos()

    while True:
        time.sleep(0.5)