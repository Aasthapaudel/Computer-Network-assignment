import bencodepy as ben
import hashlib as hash
import requests
from urllib.parse import quote_from_bytes
import socket

def decode_bencode(bencoded_value):
    """
    Decodes a bencoded value using the bencodepy library.
    """
    try:
        return ben.Bencode(encoding="utf-8").decode(bencoded_value)
    except Exception as e:
        return ben.decode(bencoded_value)

def get_torrent_info(file_path):
    """
    Extracts tracker URL, length, piece length, piece hashes, and calculates the info hash from the torrent file.
    """
    with open(file_path, "rb") as file:
        torrent_data = file.read()
        parsed = decode_bencode(torrent_data)
        tracker_url = parsed[b"announce"].decode("utf-8")
        info = parsed[b"info"]
        length = info[b"length"]
        
        # Bencode the info dictionary
        bencoded_info = ben.encode(info)
        
        # Calculate the SHA-1 hash of the bencoded info dictionary
        info_hash = hash.sha1(bencoded_info).digest()
        
        return tracker_url, info_hash, length

def get_peers(tracker_url, info_hash,length):
    
    #Makes a GET request to the tracker URL to retrieve peers.
    print(info_hash)
    # Use quote_from_bytes to correctly encode the info_hash
    encoded_info_hash = info_hash.hex()
    print(encoded_info_hash)
    params = {
        'info_hash': info_hash,
        'peer_id': b'-PC0001-' + hash.md5().digest()[0:12],  # Random peer ID
        'port': 6881,
        'uploaded': 0,
        'downloaded': 0,
        'left': length,
        'compact': 1,
        'event': 'started'
    }

    response = requests.get(tracker_url, params=params)
    decoded_response = decode_bencode(response.content)
    raw_peers = decoded_response[b"peers"]
    def decode_string(data):
        return data.decode('utf-8') if isinstance(data, bytes) else data
    
    peer_list = []
    for i in range(len(raw_peers)):
        raw_peers[i] = {decode_string(k): decode_string(v) if isinstance(v, bytes) else v for k, v in raw_peers[i].items()}
        peerElem = raw_peers[i]['ip'] + ":" + str(raw_peers[i]['port']) 
        peer_list.append(peerElem)

    return peer_list

def main(file_path):
    """
    Main function to extract tracker URL, info hash, make request to tracker, and print peers.
    """
    tracker_url, info_hash,length = get_torrent_info(file_path)
    peers = get_peers(tracker_url, info_hash,length)
    # Print peers
    for peer in peers:
        print(peer)

if __name__ == "__main__":
    file_path = "ComputerNetworks.torrent"  # Replace with the actual torrent file name
    main(file_path)
