from client import Client
from KGC import KGC
from authority import Authority
from zmqServer import ZMQserver
import time
import pyais
import matplotlib.pyplot as plt
import random

if __name__ == "__main__":
    debug = True

    KGC_url = "http://92.222.82.236:5000"
    authority_url = "http://92.222.82.236:6000"

    mmsi = 316011550
    client = Client(str(mmsi), KGC_url, "KGC_CANADA", authority_url, debug=debug, cleanup=True, simulate=False, dont_listen=True)
    client.setup()
    client.update_repos()

    time.sleep(10)

    for i in range(25):
        data1 = {'msg_type': 1, 'repeat': 0, 'mmsi': mmsi, 'turn': 0.0, 'speed': 0.0, 'accuracy': False, 'lon':120, 'lat': 50, 'course': 51.0, 'heading': 181, 'second': 15, 'maneuver': 0, 'spare_1': b'\x00', 'raim': False, 'radio': 149208}
        client.send_message(pyais.encode_dict(data1)[0].encode("ascii"))
        time.sleep(5)

    while True:
        time.sleep(0.5)