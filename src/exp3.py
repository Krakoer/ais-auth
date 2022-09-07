from client import Client
import pyais
from tqdm import tqdm

def main():
    non_critical = [1, 2, 3, 4, 5, 15, 17, 18, 19, 20, 24]
    sign_every = 10
    with open('../ais_logs/exp3.txt', 'r') as f:
        lines = f.readlines()
    
    sent = 0
    auth = {}
    buffer = []
    for line in tqdm(lines):
        buffer.append(line)
        try:
            decoded = pyais.decode(*buffer).asdict()
            # If msg is critical OR user not auth, add signature
            mmsi = decoded['mmsi']
            if decoded['msg_type'] not in non_critical or mmsi not in auth or auth[mmsi] >= sign_every:
                sent += 3
                if decoded['msg_type'] in non_critical:
                    auth[mmsi] = 0
            elif decoded['msg_type'] in non_critical:
                auth[mmsi] += 1
            sent += len(buffer)
            buffer = []
        except pyais.exceptions.MissingMultipartMessageException:
            continue
        except Exception as e:
            print(f'Error: {e}')
            buffer = []
    print(sent)

if __name__ == '__main__':
    main()