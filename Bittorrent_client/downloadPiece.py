import socket
import requests
import hashlib as hash
import bencodepy as ben


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

        # Extract piece length and pieces
        piece_length = info[b"piece length"]
        pieces = info[b"pieces"]
        
        # Calculate the list of piece hashes
        piece_hashes = [
            pieces[i * 20: (i + 1) * 20].hex()
            for i in range(len(pieces) // 20)
        ]
        
        # Bencode the info dictionary
        bencoded_info = ben.encode(info)
        
        # Calculate the SHA-1 hash of the bencoded info dictionary
        info_hash = hash.sha1(bencoded_info).digest()
        
        return tracker_url, info_hash, length, piece_length, piece_hashes
    

def get_peers(tracker_url, info_hash, length):
    """
    Makes a GET request to the tracker URL to retrieve peers.
    """
    # Print the info hash for debugging
    print(f"Info Hash (raw): {info_hash}")

    # URL encode the info hash
    encoded_info_hash = info_hash.hex()
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

def receive_message(sock):
    """
    Receives a message from the peer and returns its length prefix, message ID, and payload.
    """
    length_prefix = sock.recv(4)
    if len(length_prefix) < 4:
        raise Exception("Failed to receive the length prefix.")
    
    message_length = int.from_bytes(length_prefix, byteorder='big')
    if message_length == 0:
        return None, None, None
    print(f"Expecting to receive message of length: {message_length} bytes")

    # Adjusting to ensure we receive the full message
    message = bytearray()
    while len(message) < message_length:
        packet = sock.recv(message_length - len(message))
        if not packet:
            raise Exception("Failed to receive the full message.")
        message.extend(packet)

    if len(message) < message_length:
        raise Exception("Failed to receive the full message.")
    
    message_id = message[0]
    payload = message[1:]
    print(f"Received message of length: {message_length} bytes with ID: {message_id}")
    
    return message_length, message_id, payload

def perform_handshake(info_hash, peer_ip, peer_port):
    """
    Performs a handshake with the peer and returns the socket connection.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((peer_ip, int(peer_port)))
        
        protocol_name = b'BitTorrent protocol'
        reserved_bytes = b'\x00' * 8
        peer_id = b'-PY0001-' + b''.join([bytes([i % 256]) for i in range(12)])  # Generate a 20-byte peer_id

        handshake_msg = bytes([len(protocol_name)]) + protocol_name + reserved_bytes + info_hash + peer_id
        sock.sendall(handshake_msg)
        
        response = sock.recv(68)
        if len(response) < 68:
            print("Received an incomplete handshake response.")
            return None
        
        peer_id_received = response[48:68]
        print("Handshake successful with peer {}, received peer ID: {}".format(peer_ip, peer_id_received.hex()))
        
        return sock
    except socket.timeout:
        print("Connection timed out. The peer might be unreachable.")
    except socket.error as e:
        print(f"Socket error: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
    return None

def send_interested_message(sock):
    """
    Sends an interested message to the peer.
    """
    interested_message = b'\x00\x00\x00\x01\x02'
    sock.sendall(interested_message)
    print("Sent interested message to peer.")

def handle_peer_messages(sock):
    """
    Handles the peer messages after the handshake.
    """
    while True:
        message_length, message_id, payload = receive_message(sock)
        if message_length is None:
            continue
        
        if message_id == 5:
            print("Received bitfield message from peer.")
            send_interested_message(sock)
        elif message_id == 1:
            print("Received unchoke message from peer.")
            return True
        else:
            print(f"Received message with ID {message_id}, ignoring.")

def send_request_message(sock, index, begin, length):
    """
    Sends a request message to the peer.
    """
    message_id = b'\x06'
    payload = (
        index.to_bytes(4, byteorder='big') +
        begin.to_bytes(4, byteorder='big') +
        length.to_bytes(4, byteorder='big')
    )
    message_length = len(message_id) + len(payload)
    request_message = (
        message_length.to_bytes(4, byteorder='big') +
        message_id +
        payload
    )
    sock.sendall(request_message)
    print(f"Sent request message for piece {index}, begin {begin}, length {length}.")

def download_piece(sock, piece_index, piece_length, output_path):
    """
    Downloads a piece by sending request messages for each block and saving the piece to disk.
    """
    block_size = 16 * 1024  # 16 KiB
    blocks = []
    for begin in range(0, piece_length, block_size):
        block_length = min(block_size, piece_length - begin)
        send_request_message(sock, piece_index, begin, block_length)
        
        message_length, message_id, payload = receive_message(sock)
        if message_id == 7:
            block_index = int.from_bytes(payload[:4], byteorder='big')
            block_begin = int.from_bytes(payload[4:8], byteorder='big')
            block_data = payload[8:]
            if block_index == piece_index and block_begin == begin:
                blocks.append(block_data)
            else:
                raise Exception("Received incorrect block.")
        else:
            print(f"Received message with ID {message_id} instead of piece message (ID 7).")
            raise Exception("Did not receive a piece message.")
    

    # Save the piece data to disk
    piece_data = b''.join(blocks)
    with open(output_path, 'wb') as file:
        file.write(piece_data)
    
    print(f"Piece {piece_index} downloaded to {output_path}")
    return piece_data

def verify_piece(piece_data, expected_hash):
    """
    Verifies the integrity of the piece by comparing its hash with the expected hash.
    """
    piece_hash = hash.sha1(piece_data).digest()
    return piece_hash == expected_hash

if __name__ == "__main__":
    torrent_file = 'sample.torrent'
    tracker_url, info_hash, length, piece_length, pieces_hash = get_torrent_info(torrent_file)
    peer_list = get_peers(tracker_url, info_hash, length)
    raw_peer_list = [peer.split(":") for peer in peer_list]

    for rawPeer in raw_peer_list:
        sock = perform_handshake(info_hash, rawPeer[0], rawPeer[1])
        if sock:
            if handle_peer_messages(sock):
                print("Peer is unchoked and ready for file download.")
                piece_index = 0  # Example: download the first piece
                output_path = 'torrent.txt'
                piece_data = download_piece(sock, piece_index, piece_length, output_path)
                if verify_piece(piece_data, pieces_hash[piece_index]):
                    print(f"Piece {piece_index} downloaded to {output_path} and verified successfully.")
                else:
                    print(f"Piece {piece_index} downloaded to {output_path} but failed verification.")
            sock.close()
