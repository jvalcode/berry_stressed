
# Handles commands received from clients
# File operations will be connected later


def handle_command(cmd, data, access_level):

    if cmd == "TASK":
        return "OK@TASK COMPLETE"

    elif cmd == "DIR":
        return "ERROR@DIR not implemented yet."

    elif cmd == "UPLOAD":
        return "ERROR@UPLOAD not implemented yet."

    elif cmd == "DOWNLOAD":
        return "ERROR@DOWNLOAD not implemented yet."

    elif cmd == "DELETE":
        return "ERROR@DELETE not implemented yet."

    elif cmd == "SUBFOLDER_CREATE":
        return "ERROR@SUBFOLDER_CREATE not implemented yet."

    elif cmd == "SUBFOLDER_DELETE":
        return "ERROR@SUBFOLDER_DELETE not implemented yet."

    else:
        return "ERROR@Invalid command."

    # V1 update test