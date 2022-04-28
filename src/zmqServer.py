import zmq
import threading
import time
import random

class ZMQserver(threading.Thread):
    def __init__(self, port_pub, port_pull):
        threading.Thread.__init__(self)
        self.port_pub = port_pub
        self.port_pull = port_pull

        context = zmq.Context()
        self.pub_sock = context.socket(zmq.PUB)
        self.pub_sock.bind(f"tcp://*:{self.port_pub}")
        self.pull_sock = context.socket(zmq.PULL)
        self.pull_sock.bind(f"tcp://*:{self.port_pull}")
        self.poller = zmq.Poller()

        self.poller.register(self.pull_sock, zmq.POLLIN)

    def run(self):
        while True:
            socks = dict(self.poller.poll())
            if self.pull_sock in socks:
                _id, message = self.pull_sock.recv_multipart()
                # print(f"Server received {message} from {_id}")
                self.pub_sock.send_multipart([_id, message])