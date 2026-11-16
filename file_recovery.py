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

def resume_download(server_ip, port, filename):

    partial_file = filename + ".part"

    # Determine how much data has already been downloaded
    if os.path.exists(partial_file):
        offset = os.path.getsize(partial_file)
    else:
        offset = 0

    print("Previously downloaded:", offset, "bytes")

    try:

        # Connect to server
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect((server_ip, port))

        # Request remaining file data
        send_request(client, filename, offset)

        response = receive_response(client)

        if response["status"] != "ready":
            print("Server error:", response.get("message"))
            client.close()
            return

        total_size = response["size"]
        expected_hash = response["sha256"]

        remaining = total_size - offset

        print("Total file size:", total_size)
        print("Remaining bytes:", remaining)

        # Append remaining data to partial file
        mode = "ab" if offset > 0 else "wb"

        with open(partial_file, mode) as file:

            received = 0

            while received < remaining:

                data = client.recv(
                    min(CHUNK_SIZE, remaining - received)
                )

                if not data:
                    raise ConnectionError("Download interrupted")

                file.write(data)
                received += len(data)

                print(
                    "Downloaded:",
                    received,
                    "of",
                    remaining,
                    "remaining bytes"
                )

        client.close()

        # Verify the file integrity
        actual_hash = calculate_sha256(partial_file)

        if actual_hash == expected_hash:

            os.replace(partial_file, filename)

            print("\nDownload completed successfully!")
            print("SHA-256 verification passed.")

        else:
            print("SHA-256 verification failed.")
            print("Partial file preserved for inspection.")

    except (ConnectionError, OSError) as error:

        print("\nConnection interrupted:", error)
        print("Partial download has been preserved.")

        if os.path.exists(partial_file):
            print("Downloaded bytes:", os.path.getsize(partial_file))


if __name__ == "__main__":

    SERVER_IP = input("Enter Server IP: ")
    PORT = int(input("Enter Server Port: "))
    FILENAME = input("Enter filename to download: ")

    resume_download(SERVER_IP, PORT, FILENAME)

