import os
import socket
import threading
import time
import authentication as auth
import commands


IP = "0.0.0.0"
PORT = 4450
ADDR = (IP, PORT)
SIZE = 1024
FORMAT = "utf-8"
SERVER_PATH = "server"


# Send a complete message
def send_message(conn, message):
    data = (message + "\n").encode(FORMAT)
    conn.sendall(data)


### to handle the clients
def handle_client(conn, addr):

    print(f"[NEW CONNECTION] {addr} connected.")

    authenticated = False
    username = None
    access_level = None
    challenge = None
    challenge_time = None

    try:
        # Read one complete command at a time
        reader = conn.makefile("r", encoding=FORMAT)

        send_message(conn, "OK@Welcome to the server")

        while True:
            data = reader.readline()

            if not data:
                break

            data = data.strip()
            if not data:
                continue

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

                if username not in auth.USERS:
                    send_message(conn, "ERROR@Invalid username.")
                    continue

                # Generate challenge and retrieve salt
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

                if challenge is None or username is None:
                    send_message(conn, "ERROR@No login pending.")
                    continue

                # Save and invalidate challenge immediately
                current_challenge = challenge
                challenge = None

                if time.monotonic() - challenge_time > 30:
                    send_message(conn, "ERROR@Login challenge expired.")
                    continue

                response = data[1]

                if auth.verify_response(
                    username, current_challenge, response
                ):

                    authenticated = True
                    access_level = auth.get_access_level(username)

                    print(f"[LOGIN] {username} logged in as {access_level}")

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

            # Send commands to commands.py
            elif cmd in [
                "TASK", "DIR", "UPLOAD", "DOWNLOAD",
                "DELETE", "SUBFOLDER_CREATE",
                "SUBFOLDER_DELETE"
            ]:

                if auth.has_permission(access_level, cmd):
                    send_data = commands.handle_command(
                        cmd,
                        data,
                        access_level
                    )
                    # print(f"[COMMAND] Response: {send_data}") #also adedd line for testing
                else:
                    send_data = "ERROR@Permission denied."

                send_message(conn, send_data)

            else:
                send_message(conn, "ERROR@Invalid command.")

    except (ConnectionError, OSError) as e:
        print(f"[ERROR] Connection lost with {addr}: {e}")
    #except Exception as e: #temp lines for finding error
        #print(f"[ERROR] {type(e).__name__}: {e}")



    finally:
        print(f"{addr} disconnected")
        conn.close()


def main():
    print("Starting the server")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(ADDR)  # bind the address
    server.listen()  # start listening

    print(f"server is listening on {IP}: {PORT}")

    while True:
        conn, addr = server.accept()

        # Assign a thread for each client
        thread = threading.Thread(
            target=handle_client,
            args=(conn, addr)
        )

        thread.start()


if __name__ == "__main__":
    main()

# V1 update test