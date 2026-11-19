#Final Version
import os
import socket
import threading
import time
import authentication as auth
import commands  # no longer used, but kept for future and TASK command
from network_analysis import NetworkAnalyzer
import file_operations as filops


IP = "0.0.0.0"
PORT = 4450
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_PATH = "server"

# Store information about connected clients
active_clients = {}
clients_lock = threading.Lock() # Prevent threads from changing client information at the same time
analyzer = NetworkAnalyzer()
filops.analyzer = analyzer # allows file operations to record the network statistics

# Send a complete message
def send_message(conn, message):
    data = (message + "\n").encode(FORMAT)
    conn.sendall(data)


### to handle the clients
def handle_client(conn, addr):

    print(f"[NEW CONNECTION] {addr} connected.")

    # Default information before the client logs in
    authenticated = False
    username = None
    access_level = None

    # Add new client to the active client dictionary
    with clients_lock:
        active_clients[addr] = {
            "username": None,
            "authenticated": False,
            "access_level": None
        }
        print(f"[ACTIVE CLIENTS] {len(active_clients)}")
    
    # Used for the login challenge, so it can expire after a certain time
    challenge = None
    challenge_time = None

    try:
        # Read one complete command at a time
        reader = conn.makefile("rb")

        send_message(conn, "OK@Welcome to the server")

        while True:
            data = reader.readline().decode(FORMAT)

            if not data:
                break

            data = data.strip()
            if not data:
                continue

            # Keep the full message for file operations, but split it to find the command
            message = data
            data = data.split("@")
            cmd = data[0].upper()

            send_data = "OK@"

            if cmd == "LOGOUT":
                send_message(conn, "OK@Logging out.")
                break

            # Client requests login
            elif cmd == "LOGIN":

                if len(data) != 2:
                    send_message(conn, "ERROR@Invalid login request.")
                    continue

                username = data[1]
                authenticated = False
                access_level = None
                challenge = None

                # Reset the previous client information when a new login is attempted
                with clients_lock:
                    active_clients[addr]["username"] = None
                    active_clients[addr]["authenticated"] = False
                    active_clients[addr]["access_level"] = None

                if username not in auth.USERS:
                    send_message(conn, "ERROR@Invalid username.")
                    continue

                # Generate challenge and retrieve salt
                # This allows the password to be checked without directly sending it
                challenge = auth.generate_challenge()
                challenge_time = time.monotonic()
                salt = auth.USERS[username]["salt"].hex()

                send_data = f"CHALLENGE@{salt}@{challenge}"
                send_message(conn, send_data)

            # Client responds to challenge
            elif cmd == "RESPONSE":

                if len(data) != 2:
                    send_message(conn, "ERROR@Invalid response.")
                    continue

                # Make sure there was actually a login request first
                if challenge is None or username is None:
                    send_message(conn, "ERROR@No login pending.")
                    continue

                # Save and invalidate challenge immediately
                current_challenge = challenge
                challenge = None

                # Give the client 30 seconds to respond to the challenge
                if time.monotonic() - challenge_time > 30:
                    send_message(conn, "ERROR@Login challenge expired.")
                    continue

                response = data[1]

                # Check the response using authentication.py
                if auth.verify_response(
                    username, current_challenge, response
                ):

                    authenticated = True
                    access_level = auth.get_access_level(username)

                    print(f"[LOGIN] {username} logged in as {access_level}")

                    # Update client information after successful login
                    with clients_lock:
                        active_clients[addr]["username"] = username
                        active_clients[addr]["access_level"] = access_level
                        active_clients[addr]["authenticated"] = True

                    send_data = f"OK@Login successful. Role: {access_level}"
                    send_message(conn, send_data)

                else:
                    authenticated = False
                    access_level = None

                    print(f"[LOGIN FAILED] {addr}")
                    send_message(conn, "ERROR@Incorrect password.")

            # Prevent commands before login
            elif not authenticated:
                send_message(conn, "ERROR@You must login first.")
            # Handle OG TASK command
            elif cmd == "TASK":

                if auth.has_permission(access_level, cmd):
                    send_data = commands.handle_command(cmd, data, access_level)
                    send_message(conn, send_data)
                else:
                    send_message(conn, "ERROR@Permission denied.")

            ### File commands are handled separately in file_operations.py
            # The users access level determines which commands they can use
            elif cmd in [
                "DIR", "UPLOAD", "DOWNLOAD",
                "DELETE", "SUBFOLDER_CREATE",
                "SUBFOLDER_DELETE"
            ]:

                if auth.has_permission(access_level, cmd):
                    try:
                        filops.dispatch(conn, reader, message,
                                        access_level)
                    except filops.OperationError as e:
                        # Return the error to the client instead of ending the connection
                        send_message(conn, f"ERROR@{e}")

                else: 
                    send_message(conn, "ERROR@Permission denied.")
            else:
                send_message(conn, "ERROR@Invalid command.")
    except (ConnectionError, OSError, EOFError, ValueError) as e:
        # If a client disconnects unexpectedly, the server can still handle others
        print(f"[ERROR] Connection lost with {addr}: {e}")
   
    finally:
        # Remove disconnected client
        with clients_lock:
            active_clients.pop(addr, None)        
            print(f"[ACTIVE CLIENTS] {len(active_clients)}")
        print(f"{addr} disconnected.")
        conn.close()


### Start the server
def main():
    print("Starting the server")

    # Make sure the storage folder exists before accepting clients
    filops.STORAGE.mkdir(parents=True, exist_ok=True)
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)  # bind the address
    server.listen()  # start listening

    print(f"server is listening on {IP}: {PORT}")

    while True:
        conn, addr = server.accept()

        # Assign a thread for each client
        # This allows multiple clients to connect and use the server at once
        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr)
        )

        thread.start()


if __name__ == "__main__":
    main()
