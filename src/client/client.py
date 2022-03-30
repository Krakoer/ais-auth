import requests
import json
import sys
import subprocess
import hashlib
import zmq

def setup(ID : str):
    # Get public parameters
    res = requests.get("http://127.0.0.1:5000/params")
    res = json.loads(res.content)

    # Store them in a file
    with open("params.txt", 'w') as f:
        for k, v in res.items():
            f.write(f"{k}:{v}\n")

    print("Get public params : OK")
    
    # Request register
    res = requests.post("http://127.0.0.1:5000/register", json={"id": ID})
    partial_key = json.loads(res.content)

    print("Get partial private key : OK")
    
    # Generate the private/public keys
    res = subprocess.run(["./client", "setup"], capture_output=True, stdin=open("a.param"), text=True)
    output = res.stdout.strip()
    user_key = {}
    for l in output.splitlines():
        name = l.split(":")[0]
        value = l.split(":")[1]
        user_key[name] = value

    print("Get full private/public keys : OK")
    
    # Save all that in file
    with open("private.key", 'w') as f:
        f.write(f"xid:{user_key['xid']}\n")
        f.write(f"sid:{partial_key['sid']}\n")
    with open("public.key", 'w') as f:
        f.write(f"Pid:{user_key['Pid']}\n")
        f.write(f"Rid:{partial_key['Rid']}\n")

    print("Saving keys : OK")
    return user_key["Pid"], partial_key['Rid']

def main():
    context = zmq.Context()
    Pid, Rid = setup(sys.argv[1])
    if sys.argv[2] == "send":
        # We want to sign this message
        message = b"Coucou"
        m = hashlib.sha256()
        m.update(message)
        res = subprocess.run(["./client", "sign", m.digest()], capture_output=True, text=True, stdin=open("a.param"))
        signature = res.stdout.strip()

        # Send message, signature and public key to other client
        socket = context.socket(zmq.REQ)
        socket.connect("tcp://localhost:5555")
        socket.send(message)
        r = socket.recv()
        socket.send_string(signature)
        r = socket.recv()
        socket.send_string(sys.argv[1]) # Send ID
        r = socket.recv()
        socket.send_string(Pid)
        r = socket.recv()
        socket.send_string(Rid)
        r = socket.recv()

    elif sys.argv[2] == "recv":
        socket = context.socket(zmq.REP)
        socket.bind("tcp://*:5555")
        #  Wait for message and signature and public key to arrive
        message = socket.recv()
        print(f"Message : {message}")
        socket.send(b"")

        signature = socket.recv()
        socket.send(b"")
        print(f"Signature : {signature}")

        id_ = socket.recv()
        socket.send(b"")
        print(f"id : {id_}")

        Rid_h = socket.recv()
        socket.send(b"")
        print(f"Rid : {Rid_h}")

        Pid_h = socket.recv()
        socket.send(b"")
        print(f"Pid : {Pid_h}")

        # Verify the message
        # int verify(unsigned char *message, char *signature, unsigned char* id_h, char* Rid_b64, char* Pid_b64){
        h = hashlib.sha256()
        h.update(message)
        message = h.digest()
        h = hashlib.sha256()
        h.update(id_)
        id_ = h.digest()
        subprocess.run(["./client", "verify", message, signature, id_, Rid_h, Pid_h], stdin = open("a.param"))


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage : {sys.argv[0]} ID [send/recv]")
    main()