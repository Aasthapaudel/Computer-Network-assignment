import socket
import requests
import hashlib as hash
import bencodepy as ben
#b'\x95\x8e$\x87\xd2\xdb_A\xf9\xc0V\xbb5\xcfT~\xdf8R\x8f'
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

""" def get_peers(tracker_url, info_hash,length):
    
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

    return peer_list """

def get_peers(tracker_url, info_hash, length):
    """
    Makes a GET request to the tracker URL to retrieve peers.
    """
    # Print the info hash for debugging
    print(f"Info Hash (raw): {info_hash}")

    # URL encode the info hash
    encoded_info_hash = requests.utils.quote(info_hash)
    print(f"Encoded Info Hash: {encoded_info_hash}")

    # Generate a random peer ID
    peer_id = b'-PC0001-' + hash.md5().digest()[0:12]

    # Define the parameters for the GET request
    params = {
        'info_hash': info_hash,
        'peer_id': peer_id,
        'port': 6881,
        'uploaded': 0,
        'downloaded': 0,
        'left': length,
        'compact': 1,  # Request compact peer list
        'event': 'started'
    }

    # Send the GET request to the tracker
    try:
        response = requests.get(tracker_url, params=params, timeout=10)
        response.raise_for_status()  # Raise an error for HTTP error responses
    except requests.exceptions.RequestException as e:
        print(f"Error contacting tracker: {e}")
        return []

    # Decode the tracker response
    try:
        decoded_response = decode_bencode(response.content)
    except Exception as e:
        print(f"Error decoding response from tracker: {e}")
        return []

    # Check if the response contains 'peers'
    if b"peers" not in decoded_response:
        print("No peers found in tracker response.")
        return []

    raw_peers = decoded_response[b"peers"]

    # Determine if the peers list is in compact format
    peer_list = []

    if isinstance(raw_peers, bytes):
        # Compact format: decode as 6-byte chunks
        print("Tracker returned peers in compact format.")
        for i in range(0, len(raw_peers), 6):
            ip = socket.inet_ntoa(raw_peers[i:i + 4])
            port = int.from_bytes(raw_peers[i + 4:i + 6], byteorder='big')
            peer_list.append(f"{ip}:{port}")
    elif isinstance(raw_peers, list):
        # Non-compact format: decode each peer dictionary
        def decode_string(data):
            return data.decode('utf-8') if isinstance(data, bytes) else data
        
        for peer_dict in raw_peers:
            if isinstance(peer_dict, dict):
                # Decode each peer's information
                peer_info = {decode_string(k): decode_string(v) for k, v in peer_dict.items()}
                ip = peer_info.get('ip', '')
                port = peer_info.get('port', '')
                peer_list.append(f"{ip}:{port}")

    print(f"Found peers: {peer_list}")
    return peer_list


def perform_handshake(info_hash, peer_ip, peer_port):
    try:
        print(f"Connecting to Peer Ip {peer_ip} at port {peer_port} ........")
        # Create a socket and connect to the peer
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # Set a timeout for socket operations
        sock.connect((peer_ip, int(peer_port)))
        
        # Build handshake message
        protocol_name = b'BitTorrent protocol'
        reserved_bytes = b'\x00' * 8
        peer_id = b'-PY0001-' + b''.join([bytes([i % 256]) for i in range(12)])  # Generate a 20-byte peer_id

        handshake_msg = bytes([len(protocol_name)]) + protocol_name + reserved_bytes + info_hash + peer_id
        # Send handshake message
        sock.sendall(handshake_msg)
        
        # Receive handshake response
        response = sock.recv(68)  # According to the BitTorrent protocol, handshake response is 68 bytes
        if len(response) < 68:
            print("Received an incomplete handshake response.")
            return
        
        # Extract peer id from response
        peer_id_received = response[48:68]  # Peer id is located from byte 48 to 67 (20 bytes)
        
        # Print hexadecimal representation of peer id received
        print("Peer ID:", peer_id_received.hex(),"\n")
        
    except socket.timeout:
        print("Connection timed out. The peer might be unreachable.")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    # Example usage:
    torrent_file = 'sample.torrent'
    tracker_url,info_hash,length = get_torrent_info(torrent_file)
    peer_list = get_peers(tracker_url,info_hash,length)
    raw_peer_list = [peer.split(":") for peer in peer_list]

    for rawPeer in raw_peer_list:
        perform_handshake(info_hash,rawPeer[0],rawPeer[1])

