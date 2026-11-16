import socket
import hashlib
import os
import json

CHUNK_SIZE = 1024 * 1024  # 1 MB chunks


def send_request(sock, filename, offset):

    request = {
        "command": "download",
        "filename": filename,
        "offset": offset
    }
    sock.sendall(json.dumps(request).encode() + b"\n")

def receive_response(sock):

    data = b""

    while not data.endswith(b"\n"):
        chunk = sock.recv(1)

        if not chunk:
            raise ConnectionError("Connection lost")

        data += chunk

    return json.loads(data.decode())

def calculate_sha256(filename): #Secure Hash Algorithm 256

    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:

        while True:
            data = file.read(CHUNK_SIZE)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()
