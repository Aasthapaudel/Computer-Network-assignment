import bencodepy as ben
import hashlib as hash

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
        info_hash = hash.sha1(bencoded_info).hexdigest()
        
        # Extract piece length and pieces
        piece_length = info[b"piece length"]
        pieces = info[b"pieces"]
        
        # Calculate the list of piece hashes
        piece_hashes = [
            pieces[i * 20: (i + 1) * 20].hex()
            for i in range(len(pieces) // 20)
        ]
        
        return tracker_url, length, info_hash, piece_length, piece_hashes

def main(file_path):
    """
    Main function to extract and print the torrent file information.
    """
    tracker_url, length, info_hash, piece_length, piece_hashes = get_torrent_info(file_path)
    print(f"Tracker URL: {tracker_url}")
    print(f"Length: {length}")
    print(f"Info Hash: {info_hash}")
    print(f"Piece Length: {piece_length}")
    print("Piece Hashes:")
    for piece_hash in piece_hashes:
        print(piece_hash)

if __name__ == "__main__":
    file_path = "sample.torrent"  # Replace with the actual torrent file name
    main(file_path)
