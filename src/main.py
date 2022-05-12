from client import Client
from KGC import KGC
from authority import Authority
from zmqServer import ZMQserver
import time
import pyais
import matplotlib.pyplot as plt
import random

if __name__ == "__main__":
    debug = False

    KGC_dict = {
        "KGC1": "http://localhost:5000",
        "KGC2": "http://localhost:5001",
        "KGC3": "http://localhost:5002",
    }
    LO_url = "http://127.0.0.1:6000"
    # Setup LO
    authority = Authority(6000)
    authority.run_server()
    time.sleep(0.5)
    # Setup three KGC
    KGC1 = KGC("KGC1", 5000, LO_url)
    KGC2 = KGC("KGC2", 5001, LO_url)
    KGC3 = KGC("KGC3", 5002, LO_url)

    KGC1.setup()
    KGC2.setup()
    KGC3.setup()

    KGC1.run_server()
    KGC2.run_server()
    KGC3.run_server()

    time.sleep(1) # Time for KGCs to setup

    # Start ZMQ server for simulation
    ZMQ_serv = ZMQserver(4000, 4001, debug=debug)
    ZMQ_serv.start()

    ZMQ_serv.start_measurement()

    # mmsis = [random.randint(111111111, 999999995) for i in range(8)]
    mmsis = [111111111, 222222222, 333333333, ]
    clients = []
    for mmsi in mmsis:
        KGC_id = ["KGC1", "KGC2", "KGC3"][mmsi%3]
        new_client = Client(str(mmsi), KGC_dict[KGC_id], KGC_id, LO_url, debug=debug, cleanup=True)
        new_client.setup()
        clients.append(new_client)
        time.sleep(0.1)


    for c in clients:
        c.update_repos()

    time.sleep(0.5)

    for c in clients:
        c.start_recv_thread()



    for i in range(20):

        time.sleep(0.5)
        client = random.choice(clients)
        print(f"Sending : {client.ID}")
        data1 = {'msg_type': 1, 'repeat': 0, 'mmsi': int(client.ID), 'turn': 0.0, 'speed': 0.0, 'accuracy': False, 'lon': (random.random()-0.5)*120, 'lat': (random.random()-0.5)*50, 'course': 51.0, 'heading': 181, 'second': 15, 'maneuver': 0, 'spare_1': b'\x00', 'raim': False, 'radio': 149208}
        msg = pyais.encode_dict(data1)[0].encode("ascii")

        client.send_message(msg)
    time.sleep(0.5)

    m, q = ZMQ_serv.stop_measurement()
    print(f"Total number of bytes sent : {q}")
    plt.plot(list(m.keys()), list(m.values()))
    plt.show()
    exit()