import zmq
import threading
import time
import random

class ZMQserver(threading.Thread):
    def __init__(self, port_pub, port_pull, debug=False):
        threading.Thread.__init__(self)
        self.port_pub = port_pub
        self.port_pull = port_pull

        context = zmq.Context()
        self.pub_sock = context.socket(zmq.PUB)
        self.pub_sock.bind(f"tcp://*:{self.port_pub}")
        self.pull_sock = context.socket(zmq.PULL)
        self.pull_sock.bind(f"tcp://*:{self.port_pull}")
        self.poller = zmq.Poller()
        self.debug=debug

        self.nb_bytes=0
        self.measurements = {}
        self.measuring=False
        self.time_start = 0

        self.poller.register(self.pull_sock, zmq.POLLIN)
        self.ids = []

    def start_measurement(self):
        self.nb_bytes=0
        self.measuring = True
        self.measurements = {}
        self.time_start = time.time()

    def stop_measurement(self):
        self.measuring = False
        m = self.measurements
        q = self.nb_bytes
        self.measurements={}
        self.nb_bytes = 0
        return m, q
        

    def run(self):
        while True:
            socks = dict(self.poller.poll())
            if self.pull_sock in socks:
                _id, message = self.pull_sock.recv_multipart()
                if self.debug:
                    print(f"Server received {message} from {_id}")
                if message == b"CONNECT":
                    self.ids.append(_id)
                    self.pub_sock.send_multipart([_id, b"OK"])
                else:
                    if self.measuring:
                        self.nb_bytes += len(message)
                        dt = int(time.time()-self.time_start)
                        if not dt in self.measurements:
                            self.measurements[dt] = len(message)
                        else:
                            self.measurements[dt] += len(message)

                    for i in self.ids:
                        if i != _id:
                            if self.debug:
                                print(f"[ZMQServ]: transmit to {i}")
                            self.pub_sock.send_multipart([i, message])