from client import Client
from KGC import KGC
from authority import Authority
from zmqServer import ZMQserver
import time
import pyais
import matplotlib.pyplot as plt
import random
from argparse import ArgumentParser
import sys

def parse_file(path):
    res = {} # (timestamp, mmsi, msg)
    mmsi_set = set()
    with open(path, 'r') as f:
        lines = f.readlines()
    for l in lines:
        t, msg = l.strip().split('\t')  
        t=int(t)
        try:
            decoded = pyais.decode(msg).asdict()
            res[t] = {"mmsi": decoded["mmsi"], "msg": msg}
            mmsi_set.add(decoded["mmsi"])
        except Exception as e:
            print(e)
    return mmsi_set, res

def replay_file(file_path, auth = True, nb_kgc=5):
    # First parse file
    mmsis, log = parse_file(file_path)
    print(f"Number of boats : {len(mmsis)}")
    print(f"MMSIs : {mmsis}")

    debug = False

    KGC_dict = {f"KGC{i}" : f"http://localhost:5{i:03d}" for i in range(nb_kgc)}

    authority_url = "http://127.0.0.1:6000"
    # Setup LO
    authority = Authority(6000)
    authority.run_server()
    time.sleep(0.5)
    # Setup  KGC
    KGCs = [KGC(kgc_id, 5000+i, authority_url) for i, kgc_id in enumerate(KGC_dict.keys())]

    for k in KGCs:
        k.setup()
        time.sleep(0.1)
        k.run_server()


    # Start ZMQ server for simulation
    ZMQ_serv = ZMQserver(4000, 4001, debug=debug)
    ZMQ_serv.start()

    ZMQ_serv.start_measurement()

    clients = {}
    for mmsi in mmsis:
        KGC_id = f"KGC{mmsi%nb_kgc}" # Chose a KGC at random
        new_client = Client(str(mmsi), KGC_dict[KGC_id], KGC_id, authority_url, debug=debug, cleanup=True, auth=auth, verify=auth)
        new_client.setup()
        clients[mmsi] = new_client
        time.sleep(0.1)


    for c in clients.values():
        c.update_repos()

    time.sleep(0.5)

    for c in clients.values():
        c.start_recv_thread()

    # Replay the log
    t = 0
    played = 0
    while played < len(log):
        if t in log:
            print(t)
            to_send = log[t]
            client = clients[to_send["mmsi"]]
            client.send_message(to_send["msg"].encode("ascii"))
            played+=1
        t+=1
        time.sleep(0.0001)

    for client in clients.values():
        client.cleanup()

    m = ZMQ_serv.stop_measurement()
    time.sleep(0.5)
    for k in KGCs:
        k.stop()
    authority.stop()
    return m

if __name__ == "__main__":
    auth_m = replay_file("test_short.log")
    no_auth_m = replay_file("test_short.log", auth=False)

