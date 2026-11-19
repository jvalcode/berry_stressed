
import socket
import hashlib
import hmac
import os
import getpass
from pathlib import Path

# Server configaration
SERVER_IP = "10.200.102.209"
PORT = 4450

FORMAT = "utf-8"
CHUNK_SIZE = 1024 * 1024

DOWNLOADS = Path(__file__).resolve().parent / "downloads"

# Network communication
def send_message(sock, message):
    """Send a newline-terminated message."""
    sock.sendall((message + "\n").encode(FORMAT))

def read_message(reader):
    """Read one complete control message."""

    data = reader.readline(1024 * 1024 + 1)

    if not data:
        raise ConnectionError("Server disconnected.")

    if len(data) > 1024 * 1024 or not data.endswith(b"\n"):
        raise ValueError("Invalid server response.")

    return data.decode(FORMAT).rstrip("\r\n")

def read_status(reader):
    """Separate response status and message."""

    status, separator, message = read_message(reader).partition("@")

    if not separator:
        raise ValueError("Invalid server response.")

    return status, message

# Authentication
def authenticate(client, reader):
    """Authenticate using the existing server protocol."""

    print("\n========== LOGIN ==========")

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    # Request login
    send_message(client, f"LOGIN@{username}")

    status, message = read_status(reader)

    if status != "CHALLENGE":
        raise RuntimeError(f"Login failed: {message}")

    parts = message.split("@")

    if len(parts) != 2:
        raise ValueError("Invalid authentication challenge.")

    salt = bytes.fromhex(parts[0])
    challenge = parts[1]

    # Generate password derived key
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(FORMAT),
        salt,
        200000
    )

    # Calculate HMAC response
    response = hmac.new(
        key,
        challenge.encode(FORMAT),
        hashlib.sha256
    ).hexdigest()

    # Send authentication response
    send_message(client, f"RESPONSE@{response}")

    status, message = read_status(reader)

    if status != "OK":
        raise RuntimeError(f"Authentication failed: {message}")

    print(message)
    print("Authentication successful!")

# SHA-256 verification
def calculate_sha256(filename):
    """Calculate SHA-256 hash of a file."""

    sha256 = hashlib.sha256()

    with open(filename, "rb") as file:

        while True:
            data = file.read(CHUNK_SIZE)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()

# Resumable Download
def resume_download(client, reader, filename):
    """Download a file or resume an interrupted download."""

    DOWNLOADS.mkdir(parents=True, exist_ok=True)

    # Keep the local filename separate from server path
    local_name = Path(filename.replace("\\", "/")).name

    if not local_name or local_name in {".", ".."}:
        raise ValueError("Invalid filename.")

    target = DOWNLOADS / local_name
    partial_file = DOWNLOADS / (local_name + ".part")

    if target.exists() or target.is_symlink():
        print("File already exists:", target)
        print("Move or rename it before downloading again.")
        return

    # Determine existing downloaded bytes.
    if partial_file.exists():
        if partial_file.is_symlink() or not partial_file.is_file():
            raise ValueError("Invalid partial download file.")

        offset = partial_file.stat().st_size
    else:
        offset = 0

    print("\n========== DOWNLOAD ==========")
    print("Filename:", filename)
    print("Previously downloaded:", offset, "bytes")

    # Request remaining file data
    send_message(client, f"DOWNLOAD@{filename}@{offset}")

    status, message = read_status(reader)

    if status != "FILE":
        raise RuntimeError(f"Server error: {message}")

    parts = message.split("@")

    if len(parts) != 2:
        raise ValueError("Invalid file information from server.")

    total_size = int(parts[0])
    expected_hash = parts[1]

    if total_size < 0:
        raise ValueError("Invalid file size.")

    if len(expected_hash) != 64:
        raise ValueError("Invalid SHA-256 hash.")

    try:
        int(expected_hash, 16)
    except ValueError as exc:
        raise ValueError("Invalid SHA-256 hash.") from exc

    if offset > total_size:
        raise ValueError(
            "Partial file is larger than the server file. "
            "Delete the .part file and try again."
        )

    remaining = total_size - offset

    print("Total file size:", total_size, "bytes")
    print("Remaining bytes:", remaining)

    # Receive remaining file bytes
    mode = "ab" if offset > 0 else "wb"

    with open(partial_file, mode) as destination:

        received = 0

        while received < remaining:

            data = reader.read(
                min(CHUNK_SIZE, remaining - received)
            )

            if not data:
                raise ConnectionError("Download interrupted.")

            destination.write(data)
            received += len(data)

            print(
                f"\rDownloaded: {received}/{remaining} bytes",
                end="",
                flush=True
            )

        destination.flush()
        os.fsync(destination.fileno())

    print()

    # Receive final server response
    status, message = read_status(reader)

    if status != "OK":
        raise RuntimeError(f"Download failed: {message}")

    # Verify complete file
    print("\nVerifying SHA-256...")

    actual_hash = calculate_sha256(partial_file)

    if hmac.compare_digest(actual_hash, expected_hash):

        os.replace(partial_file, target)

        print("\nDownload completed successfully!")
        print("SHA-256 verification passed.")
        print("Saved to:", target)

    else:

        print("\nSHA-256 verification FAILED!")
        print("Partial file preserved:")
        print(partial_file)
        print("Delete the .part file to restart the download.")

# Main Function

def main():

    print("===================================")
    print("       FILE RECOVERY CLIENT")
    print("===================================")

    server_ip = input(
        f"Enter Server IP [{SERVER_IP}]: "
    ).strip() or SERVER_IP

    port_input = input(
        f"Enter Server Port [{PORT}]: "
    ).strip()

    port = int(port_input) if port_input else PORT

    filename = input(
        "Enter filename to recover: "
    ).strip()

    if not filename:
        print("Filename cannot be empty.")
        return

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reader = None

    try:

        print("\nConnecting to server...")

        client.connect((server_ip, port))

        # Use the same buffered reader for control messages and binary file data.
        reader = client.makefile("rb")

        status, message = read_status(reader)

        if status != "OK":
            raise RuntimeError(message)

        print(message)

        # Authenticate first.
        authenticate(client, reader)

        # Resume or start download.
        resume_download(client, reader, filename)

    except (ConnectionError, OSError, ValueError,
            RuntimeError, EOFError) as error:

        print("\nDownload interrupted or failed:", error)

        DOWNLOADS.mkdir(parents=True, exist_ok=True)

        local_name = Path(filename.replace("\\", "/")).name
        partial_file = DOWNLOADS / (local_name + ".part")

        if partial_file.exists():
            print("Partial download preserved.")
            print("Downloaded bytes:", partial_file.stat().st_size)

    finally:

        if reader is not None:
            reader.close()

        client.close()

        print("\nDisconnected from server.")

# PROGRAM ENTRY POINT

if __name__ == "__main__":
    main()
