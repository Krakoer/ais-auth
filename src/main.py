from client import Client
from KGC import KGC
from zmqServer import ZMQserver
import time

if __name__ == "__main__":
    KGC_dict = {
        "KGC1": "http://localhost:5000",
        "KGC2": "http://localhost:5001",
    }
    # Setup two KGC
    KGC1 = KGC("KGC1", 5000)
    KGC2 = KGC("KGC2", 5001)

    KGC1.setup()
    KGC2.setup()

    KGC1.run_server()
    KGC2.run_server()

    time.sleep(1) # Time for KGCs to setup

    # Start ZMQ server for simulation
    ZMQ_serv = ZMQserver(4000, 4001)
    ZMQ_serv.start()

    client1 = Client("888888888", "a.param", KGC_dict, "KGC1")
    client2 = Client("444444444", "a.param", KGC_dict, "KGC2")

    client1.setup_crypto()
    client2.setup_crypto()

    time.sleep(0.5)

    client1.start_recv_thread()
    client2.start_recv_thread()

    time.sleep(0.5)

    client1.send(b"Coucou!")

    time.sleep(0.5)

    client2.send(b"Yooo!")

    try:
        while(1):
            time.sleep(0.5)
    except KeyboardInterrupt:
        exit()