from client import Client
from KGC import KGC
from authority import Authority
import time
import pyais
import matplotlib.pyplot as plt
import random

if __name__ == "__main__":
    debug = True
    KGC_url = "http://127.0.0.1:5000"
    KGC_id = "KGC1"
    authority_url = "http://127.0.0.1:6000"
    # Setup LO
    authority = Authority(6000, )
    authority.run_server()
    time.sleep(0.5)
    # Setup KGC
    KGC1 = KGC(KGC_id, 5000, authority_url, debug=debug)

    KGC1.setup()
  
    KGC1.run_server()

    time.sleep(1) # Time for KGC setup

    client1 = Client(888888888, KGC_url, KGC_id, authority_url, debug=debug, simulate=False)
    client2 = Client(777777777, KGC_url, KGC_id, authority_url, debug=debug, simulate=False)
    client1.setup()
    client2.setup()
    client2.start_recv_thread()
    time.sleep(5)
    data1 = {'msg_type': 1, 'repeat': 0, 'mmsi': int(client1.mmsi), 'turn': 0.0, 'speed': 0.0, 'accuracy': False, 'lon':120, 'lat': 50, 'course': 51.0, 'heading': 181, 'second': 15, 'maneuver': 0, 'spare_1': b'\x00', 'raim': False, 'radio': 149208}
    msg = pyais.encode_dict(data1)[0].encode("ascii")
    client1.send_message(msg)
    time.sleep(5)