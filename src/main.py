from client import Client
from KGC import KGC
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

    client1 = Client("888888888", "a.param", KGC_dict, "KGC1")
    client2 = Client("444444444", "a.param", KGC_dict, "KGC2")

    client1.setup()
    client2.setup()

    try:
        while(1):
            time.sleep(0.5)
    except KeyboardInterrupt:
        exit()