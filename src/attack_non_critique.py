from client import Client
from authority import Authority
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

    input('Click enter when ready')

    with open("../ais_logs/AIS_log_exp2.txt", 'r') as f:
        messages = f.readlines()

    for i, m in enumerate(messages):
        if i >= len(messages)//2:
            data = pyais.decode(m.strip()).asdict()
            data["lon"] += 0.01
            data["lat"] += 0.01
            m = pyais.encode_dict(data)[0]
        client.send_message(m.strip().encode('ascii'))
        time.sleep(1)