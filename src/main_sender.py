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

    authority_url = "http://92.222.82.236:3000"

    mmsi_attack = 316011550
    client_attack = Client(str(mmsi_attack), authority_url, debug=debug, cleanup=True, simulate=False, dont_listen=True, auth=False)
    client_attack.setup()
    client_attack.update_repos()

    mmsi_gentil = 123456789
    client_gentil = Client(str(mmsi_gentil), authority_url, debug=debug, cleanup=True, simulate=False, dont_listen=True, auth=True)
    client_gentil.setup()
    client_gentil.update_repos()

    print("Parsing file...")
    with open("../ais_attack.txt") as f:
        ais_messages_attack = []
        for line in f.readlines():
            if line.strip():
                d = pyais.decode(line.strip()).asdict()
                d["mmsi"] = mmsi_attack # Change the mmsi !
                # print(d)
                ais_messages_attack.append(pyais.encode_dict(d)[0].encode('ascii'))
                # print(ais_messages[-1])

    print("Parsing file...")
    with open("../ais_gentil.txt") as f:
        ais_messages_gentil = []
        for line in f.readlines():
            if line.strip():
                d = pyais.decode(line.strip()).asdict()
                d["mmsi"] = mmsi_gentil # Change the mmsi !
                # print(d)
                ais_messages_gentil.append(pyais.encode_dict(d)[0].encode('ascii'))
                # print(ais_messages[-1])

    input("Press ENTER when ready to start")

    for attack, gentil in zip(ais_messages_attack, ais_messages_gentil):
        # data1 = {'msg_type': 1, 'repeat': 0, 'mmsi': mmsi, 'turn': 0.0, 'speed': 0.0, 'accuracy': False, 'lon':45.35, 'lat': -73.40, 'course': 51.0, 'heading': 181, 'second': 15, 'maneuver': 0, 'spare_1': b'\x00', 'raim': False, 'radio': 149208}
        # client.send_message(pyais.encode_dict(data1)[0].encode("ascii"))
        client_attack.send_message(attack)
        time.sleep(0.5)
        client_gentil.send_message(gentil)
        time.sleep(0.5)

    while True:
        time.sleep(0.5)