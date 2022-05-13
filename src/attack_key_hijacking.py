from KGC import KGC
from malicious_client import EvilClient
from client import Client
from authority import Authority
import time
from zmqServer import ZMQserver
import random
import pyais

if __name__=="__main__":
    debug = True
    LO = Authority(6000)
    LO_url = "http://127.0.0.1:6000"
    LO.run_server()

    time.sleep(0.5)

    KGC1 = KGC("KGC1", 5000, LO_url)
    KGC2 = KGC("KGC2", 5001, LO_url)

    KGC1.setup()
    KGC2.setup()
    KGC1.run_server()
    KGC2.run_server()

    time.sleep(0.5)

    ZMQ_serv = ZMQserver(4000, 4001)
    ZMQ_serv.start()

    c1 = Client("111111111", "http://127.0.0.1:5000", "KGC1", LO_url, debug=debug)
    c2 = Client("222222222", "http://127.0.0.1:5001", "KGC2", LO_url, debug=debug)
    c_evil = EvilClient("333333333", "http://127.0.0.1:5001", "KGC2", LO_url, target="222222222", debug=debug)

    c1.setup()
    c2.setup()
    c_evil.setup()

    time.sleep(0.5)

    c1.update_repos()
    c2.update_repos()
    c_evil.update_repos()

    time.sleep(0.5)

    c1.start_recv_thread()
    c_evil.start_recv_thread()

    time.sleep(0.5)

    # Manually remove entry
    c1.public_key_repo.pop("222222222")

    # Should be intercepted by evil
    c1.ask_public_key("222222222")

    time.sleep(2)

    data1 = {'msg_type': 1, 'repeat': 0, 'mmsi': 222222222, 'turn': 0.0, 'speed': 0.0, 'accuracy': False, 'lon': (random.random()-0.5)*120, 'lat': (random.random()-0.5)*50, 'course': 51.0, 'heading': 181, 'second': 15, 'maneuver': 0, 'spare_1': b'\x00', 'raim': False, 'radio': 149208}
    msg = pyais.encode_dict(data1)[0].encode("ascii")
    c_evil.send_message(msg)

    time.sleep(0.5)

