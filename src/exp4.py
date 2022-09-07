from authority import Authority
from client import Client
from zmqServer import ZMQserver
from pyais import encode_dict
import time

def main():
    auth = Authority()
    auth.run_server()
    auth_url = "http://127.0.0.1:3000"

    zmqS = ZMQserver(4000, 4001)
    zmqS.start()

    mmsi_A = 111111111
    mmsi_B = 222222222
    mmsi_E = 333333333

    A = Client(mmsi_A, auth_url, dont_listen=True)
    B = Client(mmsi_B, auth_url, dont_listen=True, debug=True)
    E = Client(mmsi_E, auth_url, dont_listen=True, debug=True)

    A.setup()
    B.setup()
    E.setup()
    
    time.sleep(1)

    B.start_recv_thread()

    # Remplacement de la clé publique de A (la victime dont l'identité est usurpée)
    # par la clé de E (l'attaquant) dans le répertoire de B (la victime de l'attaque)
    B.public_key_repo[mmsi_A] = E.public_key

    # Tentative d'envoi d'un message par E avec le MMSI de A
    msg = encode_dict({'msg_type':1, 'mmsi': mmsi_A})[0].encode('ascii')
    E.send_message(msg)
    
    
if __name__ == '__main__':
    main()