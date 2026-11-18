import socket
import getpass
import hashlib
import hmac
import file_operations as filops



# Windows server IP
IP = "10.200.102.209"
PORT = 4450
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_DATA_PATH = "server_data"


# Send a complete message
def send_message(client, message):
    data = (message + "\n").encode(FORMAT)
    client.sendall(data)


# Generate response to server challenge
def create_response(password, salt, challenge):

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(FORMAT),
        salt,
        200000
    )

    response = hmac.new(
        key,
        challenge.encode(FORMAT),
        hashlib.sha256
    )

    return response.hexdigest()


# Display commands based on account type
def display_menu(access_level):

    print("\nAvailable Commands:")
    print("TASK")
    print("DIR")
    print("UPLOAD")
    print("DOWNLOAD")
    print("SUBFOLDER_CREATE")

    if access_level == "admin":
        print("DELETE")
        print("SUBFOLDER_DELETE")

    print("LOGOUT")


def main():

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client.connect(ADDR)

        # Receive complete messages from server
        reader = client.makefile("rb")
        data = reader.readline().decode(FORMAT).strip()
        cmd, msg = data.split("@", 1)

        if cmd == "OK":
            print(msg)

        # Login information
        authenticated = False
        access_level = None

        while not authenticated:

            print("\nLogin Required")

            username = input("Username: ")
            password = getpass.getpass("Password: ")

            # Request login
            send_message(client, f"LOGIN@{username}")

            data = reader.readline().decode(FORMAT).strip()

            if not data:
                print("Server disconnected.")
                return

            parts = data.split("@")

            if parts[0] == "ERROR":
                print(parts[1])
                continue

            if parts[0] != "CHALLENGE" or len(parts) != 3:
                print("Invalid server response.")
                return

            salt = bytes.fromhex(parts[1])
            challenge = parts[2]

            # Calculate HMAC response
            response = create_response(
                password,
                salt,
                challenge
            )

            send_message(client, f"RESPONSE@{response}")

            # Receive authentication result
            data = reader.readline().decode(FORMAT).strip()

            if not data:
                print("Server disconnected.")
                return

            cmd, msg = data.split("@", 1)

            if cmd == "OK":
                print(msg)
                authenticated = True

                # Save account role for command menu
                access_level = msg.split("Role: ")[-1]

            else:
                print(msg)

        # Commands after login
        while authenticated:

            display_menu(access_level)

            data = input("\n> ").strip()

            if not data:
                continue

            parts = data.split(" ", 1)
            cmd = parts[0].upper()

            # Let file_operations.py handle file commands
            argument = parts[1] if len(parts) > 1 else ""
            if filops.run_file_command(client, reader, cmd, argument):
                continue

            # Send command to server
            if len(parts) > 1:
                message = cmd + "@" + parts[1]
            else:
                message = cmd

            send_message(client, message)

            # Receive response
            data = reader.readline().decode(FORMAT)

            if not data:
                print("Server disconnected.")
                break

            data = data.strip()
            status, msg = data.split("@", 1)

            print(msg)

            if cmd == "LOGOUT":
                break

    except (ConnectionError, OSError) as e:
        print(f"Connection error: {e}")

    finally:
        print("Disconnected from the server.")
        client.close()


if __name__ == "__main__":
    main()
