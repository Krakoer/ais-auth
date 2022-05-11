from client import Client
from KGC import KGC
from authority import Authority
from zmqServer import ZMQserver
import time
import pyais

if __name__ == "__main__":
    KGC_dict = {
        "KGC1": "http://localhost:5000",
        "KGC2": "http://localhost:5001",
    }
    LO_url = "http://127.0.0.1:6000"
    # Setup LO
    authority = Authority(6000)
    authority.run_server()
    time.sleep(0.5)
    # Setup two KGC
    KGC1 = KGC("KGC1", 5000, LO_url)
    KGC2 = KGC("KGC2", 5001, LO_url)

    KGC1.setup()
    KGC2.setup()

    KGC1.run_server()
    KGC2.run_server()

    time.sleep(1) # Time for KGCs to setup

    # Start ZMQ server for simulation
    ZMQ_serv = ZMQserver(4000, 4001, )
    ZMQ_serv.start()

    client1 = Client("888888888", KGC_dict["KGC1"], "KGC1", LO_url)
    client2 = Client("444444444", KGC_dict["KGC2"], "KGC2", LO_url)
    client3 = Client("111111111", KGC_dict["KGC2"], "KGC2", LO_url)

    client1.setup()
    client2.setup()
    client3.setup()

    time.sleep(0.5)

    client1.update_repos()
    client2.update_repos()
    client3.update_repos()

    time.sleep(0.5)


    client1.start_recv_thread()
    client2.start_recv_thread()
    client3.start_recv_thread()

    time.sleep(0.5)

    data1 = {'msg_type': 1, 'repeat': 0, 'mmsi': 111111111, 'turn': 0.0, 'speed': 0.0, 'accuracy': False, 'lon': -122.345833, 'lat': 47.582833, 'course': 51.0, 'heading': 181, 'second': 15, 'maneuver': 0, 'spare_1': b'\x00', 'raim': False, 'radio': 149208}
    msg = pyais.encode_dict(data1)[0].encode("ascii")

    client3.send_message(msg)

    time.sleep(0.5)

    data2 = {'msg_type': 1, 'repeat': 0, 'mmsi': 111111111, 'turn': 0.0, 'speed': 0.0, 'accuracy': False, 'lon': -122.345833, 'lat': 47.582833, 'course': 51.0, 'heading': 181, 'second': 15, 'maneuver': 0, 'spare_1': b'\x00', 'raim': False, 'radio': 149208}
    msg = pyais.encode_dict(data2)[0].encode("ascii")

    client3.send_message(msg)