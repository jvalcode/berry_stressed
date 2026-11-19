#Final Version
#Client 1
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

    # Use the password and salt to create the key for authentication
    # Same method as the server uses so the responses can be compared
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(FORMAT),
        salt,
        200000
    )

    # Use the challenge from the server to create the response
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

    # Only admins have access to deleting files and folders
    if access_level == "admin":
        print("DELETE")
        print("SUBFOLDER_DELETE")

    print("LOGOUT")


def main():

    # Create the client socket for connecting to the server
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

        ### Keep asking for login until the server accepts it
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

            # If the username is wrong or another error happens, try again
            if parts[0] == "ERROR":
                print(parts[1])
                continue

            if parts[0] != "CHALLENGE" or len(parts) != 3:
                print("Invalid server response.")
                return

            # Get the salt and challenge that the server sent
            salt = bytes.fromhex(parts[1])
            challenge = parts[2]

            # Calculate HMAC response
            response = create_response(
                password,
                salt,
                challenge
            )

            # Send the response back instead of sending the actual password
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

            # Separate the command from any filename or other arguments
            parts = data.split(" ", 1)
            cmd = parts[0].upper()

            # Let file_operations.py handle file commands
            # This keeps the upload/download code out of the main client file
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

            # End the command loop after logging out
            if cmd == "LOGOUT":
                break

    # Handle problems connecting to the server or losing the connection
    except (ConnectionError, OSError) as e:
        print(f"Connection error: {e}")

    finally:
        print("Disconnected from the server.")
        client.close()


if __name__ == "__main__":
    main()
