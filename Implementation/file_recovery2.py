
import socket
import getpass
import hashlib
import os
from pathlib import Path

import file_operations as filops
import client1


# Server configuration
SERVER_IP = "10.200.102.209"  # Change to server's IP
PORT = 4450

CHUNK_SIZE = 64 * 1024

# Save incomplete and completed downloads here
DOWNLOADS = Path(__file__).resolve().parent / "downloads"


def calculate_sha256(filename):
    """Calculate SHA-256 hash without loading the entire file."""

    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:
        while True:
            data = file.read(CHUNK_SIZE)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


def authenticate(client, reader):
    """Authenticate using the existing challenge-response system."""

    print("\nLogin Required")

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    filops.send_message(client, f"LOGIN@{username}")

    status, message = filops.read_status(reader)

    if status == "ERROR":
        print("Login failed:", message)
        return False

    if status != "CHALLENGE":
        print("Unexpected server response:", status)
        return False

    parts = message.split("@")

    if len(parts) != 2:
        print("Invalid authentication challenge.")
        return False

    salt = bytes.fromhex(parts[0])
    challenge = parts[1]

    response = client1.create_response(
        password,
        salt,
        challenge
    )

    filops.send_message(client, f"RESPONSE@{response}")

    status, message = filops.read_status(reader)

    if status == "OK":
        print(message)
        return True

    print("Authentication failed:", message)
    return False


def resume_download(server_ip, port, filename):

    DOWNLOADS.mkdir(parents=True, exist_ok=True)

    # Keep the server filename separate from the local filename
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]

    if not name or name in {".", ".."}:
        print("Invalid filename.")
        return

    final_file = DOWNLOADS / name
    partial_file = DOWNLOADS / (name + ".part")

    if final_file.exists():
        print("A completed file with this name already exists.")
        return

    # Determine how much has already been downloaded
    if partial_file.exists():
        offset = partial_file.stat().st_size
    else:
        offset = 0

    print("\nPreviously downloaded:", offset, "bytes")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reader = None

    try:
        # Connect to existing server
        client.connect((server_ip, port))

        # Use the same buffered reader as the normal client
        reader = client.makefile("rb")

        # Read welcome message.
        status, message = filops.read_status(reader)

        if status != "OK":
            print("Server connection failed:", message)
            return

        print(message)

        # Authenticate before requesting the file
        if not authenticate(client, reader):
            return

        # Request the remaining portion of the file
        filops.send_message(
            client,
            f"DOWNLOAD@{filename}@{offset}"
        )

        status, message = filops.read_status(reader)

        if status != "FILE":
            print("Server error:", message)
            return

        # Receive file size and SHA-256 hash
        parts = message.split("@")

        if len(parts) != 2:
            raise ValueError("Invalid file information from server.")

        total_size = int(parts[0])
        expected_hash = parts[1].lower()

        if total_size < 0 or offset > total_size:
            raise ValueError("Invalid file size or resume offset.")

        remaining = total_size - offset

        print("\nTotal file size:", total_size, "bytes")
        print("Previously downloaded:", offset, "bytes")
        print("Remaining bytes:", remaining)

        # Append remaining bytes to the partial file
        mode = "ab" if offset > 0 else "wb"

        received = 0

        with open(partial_file, mode) as file:

            while received < remaining:

                data = reader.read(
                    min(CHUNK_SIZE, remaining - received)
                )

                if not data:
                    raise ConnectionError(
                        "Download interrupted. Partial file preserved."
                    )

                file.write(data)
                received += len(data)

                file.flush()

                print(
                    f"\rDownloaded: {received:,} / {remaining:,} remaining bytes",
                    end="",
                    flush=True
                )

        print()

        # Confirm server completed the transfer
        status, message = filops.read_status(reader)

        if status != "OK":
            print("Server transfer error:", message)
            return

        print(message)

        # Verify the complete file
        print("\nVerifying SHA-256...")

        actual_hash = calculate_sha256(partial_file)

        if actual_hash != expected_hash:
            print("SHA-256 verification FAILED.")
            print("Partial file preserved for inspection.")
            return

        # Rename the partial file only after successful verification
        os.replace(partial_file, final_file)

        print("\nDOWNLOAD COMPLETED SUCCESSFULLY!")
        print("SHA-256 verification PASSED.")
        print("Saved location:", final_file)

    except (ConnectionError, OSError, ValueError) as error:

        print("\nConnection or download error:", error)
        print("Partial download has been preserved.")

        if partial_file.exists():
            print(
                "Downloaded bytes:",
                partial_file.stat().st_size
            )

    finally:

        if reader is not None:
            reader.close()

        client.close()


if __name__ == "__main__":

    print("===================================")
    print("       FILE RECOVERY SYSTEM")
    print("===================================")

    filename = input("Enter server filename to recover: ").strip()

    resume_download(
        SERVER_IP,
        PORT,
        filename
    )
