import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path
from threading import Lock
import time
import hashlib

analyzer = None # ensure the analyzer is available to the file_operations module, 
            #but it will be set in Server.py after the NetworkAnalyzer is created


# Shared message and transfer helpers
SIZE = 64 * 1024
FORMAT = "utf-8"
MAX_LINE = 1024 * 1024

def send_message(sock, message):
    if "\n" in message or "\r" in message:
        raise ValueError("A control message must be one line.")
    data = (message + "\n").encode(FORMAT)
    if len(data) > MAX_LINE:
        raise ValueError("Control message is too long.")
    sock.sendall(data)


def read_message(reader):
    line = reader.readline(MAX_LINE + 1)
    if not line:
        raise EOFError("The other computer closed the connection.")
    if len(line) > MAX_LINE or not line.endswith(b"\n"):
        raise ValueError("Incomplete or oversized control message.")
    return line.decode(FORMAT).rstrip("\r\n")


def read_status(reader):
    status, separator, message = read_message(reader).partition("@")
    if not separator:
        raise ValueError("Expected a server reply in STATUS@message format.")
    return status, message


def send_bytes(sock, source, count):
    while count:
        chunk = source.read(min(SIZE, count))
        if not chunk:
            raise EOFError("The source file ended before the advertised size.")
        sock.sendall(chunk)
        count -= len(chunk)


def receive_bytes(reader, destination, count):
    # Reuse the SAME binary reader used for control lines. It may already
    # have buffered the first bytes of the file.
    while count:
        chunk = reader.read(min(SIZE, count))
        if not chunk:
            raise EOFError("The connection closed before the transfer finished.")
        destination.write(chunk)
        count -= len(chunk)


# Server-side operations
STORAGE = Path(__file__).resolve().parent / "server"
ACTIVE = set()
LOCK = Lock()
MAX_FILE = 10 * 1024**3
WINDOWS_DEVICE = re.compile(r"(?i)^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)")


class OperationError(Exception):
    """An error detected at a command boundary, so the session can continue."""


def storage_path(name):
    root = STORAGE.resolve()
    parts = name.replace("\\", "/").split("/")
    if not name or any(
        not part or part in {".", ".."} or part.endswith((" ", "."))
        or WINDOWS_DEVICE.match(part)
        or any(ord(char) < 32 or char in '<>:"|?*@' for char in part)
        for part in parts
    ):
        raise OperationError("Enter a valid relative path inside the server storage folder.")
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise OperationError("Symbolic links are not supported.")
    path = path.resolve()
    if not path.is_relative_to(root) or path == root:
        raise OperationError("That path is outside server_storage.")
    return path


@contextmanager
def reserve(path):
    with LOCK:
        if path in ACTIVE:
            raise OperationError("File is currently being processed.")
        ACTIVE.add(path)
    try:
        yield
    finally:
        with LOCK:
            ACTIVE.remove(path)


def directory(sock):
    try:
        names = sorted(
            item.name + ("/" if item.is_dir() else "")
            for item in STORAGE.iterdir()
            if not item.name.startswith(".upload-")
        )
    except OSError as exc:
        raise OperationError("Could not read the server storage folder.") from exc
    send_message(sock, "LIST@" + json.dumps(names))


def upload(sock, reader, args):
    name, separator, raw_count = args.rpartition("@")
    if not separator or not raw_count.isascii() or not raw_count.isdecimal() or len(raw_count) > 11:
        raise OperationError("Upload requires a filename and a valid byte count.")
    count = int(raw_count)
    if count > MAX_FILE:
        raise OperationError("File exceeds the 10 GiB upload limit.")

    path = storage_path(name)
    with reserve(path):
        if not path.parent.is_dir():
            raise OperationError("The destination folder does not exist.")
        if path.exists():
            if not path.is_file():
                raise OperationError("That destination is not a file.")
            send_message(sock, "EXISTS@Overwrite the existing server file?")
            decision = read_message(reader)
            if decision == "CANCEL":
                send_message(sock, "OK@Upload cancelled. Original kept.")
                return
            if decision != "OVERWRITE":
                raise OperationError("Expected OVERWRITE or CANCEL.")

        try:
            destination = tempfile.NamedTemporaryFile(
                mode="wb", dir=path.parent, prefix=".upload-", delete=False
            )
        except OSError as exc:
            raise OperationError("Could not create the upload file.") from exc

        temporary = Path(destination.name)
        try:
            with destination:
                send_message(sock, "READY@Send file bytes.")
                start_time = time.perf_counter()
                receive_bytes(reader, destination, count)
                transfer_time = time.perf_counter() - start_time
            try:
                os.replace(temporary, path)
            except OSError as exc:
                raise OperationError("Could not save the uploaded file.") from exc
        finally:
            temporary.unlink(missing_ok=True)
        send_message(sock, "OK@Upload complete.")
        analyzer.record_transfer( client=str(sock.getpeername()),
            operation="Upload",
            filename=name, file_size=count / (1024 * 1024),
            transfer_time=transfer_time, response_time = 0 )

def download(sock, name, offset=None):
    path = storage_path(name)

    with reserve(path):
        try:
            if not path.is_file():
                raise OperationError("File not found.")

            source = path.open("rb")

        except FileNotFoundError as exc:
            raise OperationError("File not found.") from exc

        except OSError as exc:
            raise OperationError("Could not open the requested file.") from exc

        with source:
            count = os.fstat(source.fileno()).st_size

            # Calculate SHA-256 of the complete file
            import hashlib

            sha256 = hashlib.sha256()

            while True:
                chunk = source.read(SIZE)

                if not chunk:
                    break

                sha256.update(chunk)

            file_hash = sha256.hexdigest()

            # Validate resume offset
            if offset is None:
                offset = 0

            if offset < 0 or offset > count:
                raise OperationError("Invalid download offset.")

            # Move to requested position
            source.seek(offset)

            # Send file information
            send_message(
                sock,
                f"FILE@{count}@{file_hash}"
            )

            # Send remaining bytes
            start_time = time.perf_counter()

            send_bytes(
                sock,
                source,
                count - offset
            )

            transfer_time = time.perf_counter() - start_time

        # Confirm transfer completion
        send_message(sock, "OK@Download complete.")

        # Record network statistics
        if analyzer is not None:
            analyzer.record_transfer(
                client=str(sock.getpeername()),
                operation="Download",
                filename=name,
                file_size=count / (1024 * 1024),
                transfer_time=transfer_time,
                response_time=0
            )

#def download(sock, name):
    #path = storage_path(name)
    #with reserve(path):
        #try:
            #if not path.is_file():
                #raise OperationError("File not found.")
           # source = path.open("rb")
       # except FileNotFoundError as exc:
          #  raise OperationError("File not found.") from exc
      #  except OSError as exc:
         #   raise OperationError("Could not open the requested file.") from exc
       # with source:
         #   count = os.fstat(source.fileno()).st_size
           # send_message(sock, f"FILE@{count}")
           # start_time = time.perf_counter()
          #  send_bytes(sock, source, count)
          #  transfer_time = time.perf_counter() - start_time
       # send_message(sock, "OK@Download complete.")

        #analyzer.record_transfer( client=str(sock.getpeername()),
            #operation="Download",
            #filename=name, file_size=count / (1024 * 1024),
           # transfer_time=transfer_time, response_time = 0 )
        
def delete(sock, name):
    path = storage_path(name)
    with reserve(path):
        if not path.is_file():
            raise OperationError("File not found.")
        try:
            path.unlink()
        except FileNotFoundError as exc:
            raise OperationError("File not found.") from exc
        except OSError as exc:
            raise OperationError("Could not delete the file.") from exc
    send_message(sock, "OK@File deleted.")


def subfolder(sock, action, name):
    path = storage_path(name)
    with LOCK:
        if any(active == path or path in active.parents for active in ACTIVE):
            raise OperationError("Folder contains a file currently being processed.")
        try:
            if action == "create":
                path.mkdir()
            else:
                # Do not recursively remove the user's data.
                path.rmdir()
        except FileExistsError as exc:
            raise OperationError("That name already exists.") from exc
        except FileNotFoundError as exc:
            raise OperationError("Folder or parent folder not found.") from exc
        except OSError as exc:
            raise OperationError(
                "Could not remove folder. Check that it is empty and writable."
                if action == "delete" else "Could not create folder."
            ) from exc
    send_message(sock, "OK@Folder created." if action == "create" else "OK@Folder deleted.")

 
def dispatch(sock, reader, message, role):
    command, _, args = message.partition("@")

    if command in {"DELETE", "SUBFOLDER_DELETE"} and role != "admin":
        raise OperationError("This command requires an admin account.")

    if command == "DIR":
        directory(sock)

    elif command == "UPLOAD":
        upload(sock, reader, args)

    elif command == "DOWNLOAD":

        # Separate filename and optional byte offset.
        name, separator, raw_offset = args.rpartition("@")

        if separator:

            if (
                not raw_offset.isascii()
                or not raw_offset.isdecimal()
                or len(raw_offset) > 11
            ):
                raise OperationError("Invalid download offset.")

            offset = int(raw_offset)

            download(sock, name, offset)

        else:
            # Original client download command.
            download(sock, args)

    elif command == "DELETE":
        delete(sock, args)

    elif command in {"SUBFOLDER_CREATE", "SUBFOLDER_DELETE"}:
        subfolder(
            sock,
            "create" if command == "SUBFOLDER_CREATE" else "delete",
            args
        )

    else:
        raise OperationError("Unknown command.")

#def dispatch(sock, reader, message, role):
    #command, _, args = message.partition("@")
    #if command in {"DELETE", "SUBFOLDER_DELETE"} and role != "admin":
     #   raise OperationError("This command requires an admin account.")
    #if command == "DIR":
     #   directory(sock)
    #elif command == "UPLOAD":
     #   upload(sock, reader, args)
    #elif command == "DOWNLOAD":
     #   download(sock, args)
    #elif command == "DELETE":
     #   delete(sock, args)
    #elif command in {"SUBFOLDER_CREATE", "SUBFOLDER_DELETE"}:
     #   subfolder(sock, "create" if command == "SUBFOLDER_CREATE" else "delete", args)
    #else:
     #   raise OperationError("Unknown command.")


# Client-side operations
DOWNLOADS = Path(__file__).resolve().parent / "downloads"


def client_upload(client, reader, argument):
    # UPLOAD takes a local path. Send the basename, not the client's full path.
    path = Path(argument)
    try:
        source = path.open("rb")
    except OSError as exc:
        print(f"Could not open the local file: {exc}")
        return

    with source:
        size = os.fstat(source.fileno()).st_size
        send_message(client, f"UPLOAD@{path.name}@{size}")
        status, message = read_status(reader)
        if status == "EXISTS":
            answer = input(message + " [y/N] ").strip().lower()
            if answer not in {"y", "yes"}:
                send_message(client, "CANCEL")
                print(read_status(reader)[1])
                return
            send_message(client, "OVERWRITE")
            status, message = read_status(reader)
        if status != "READY":
            print(message)
            return

        send_bytes(client, source, size)
        print(read_status(reader)[1])

def client_download(client, reader, argument):
    name = argument.replace("\\", "/").rsplit("/", 1)[-1]
    if not name or name in {".", ".."}:
        print("Usage: DOWNLOAD filename")
        return

    target = DOWNLOADS / name

    try:
        DOWNLOADS.mkdir(exist_ok=True)
        if target.exists() or target.is_symlink():
            print(f"Local file already exists: {target}. Move it before retrying.")
            return

        destination = tempfile.NamedTemporaryFile(
            mode="wb", dir=DOWNLOADS, prefix=".download-", delete=False
        )
    except OSError as exc:
        print(f"Could not create the local download: {exc}")
        return

    temporary = Path(destination.name)

    try:
        with destination:
            send_message(client, f"DOWNLOAD@{argument}")
            status, message = read_status(reader)
            if status != "FILE":
                print(message)
                return

            # The server sends the header as size@checksum.
            size_text, expected_checksum = message.split("@", 1)
            count = int(size_text)
            if count < 0:
                raise ValueError("Invalid download size.")

            receive_bytes(reader, destination, count)

            status, message = read_status(reader)
            if status != "OK":
                print(message)
                return

        # Verify the temporary file before saving it under its final name.
        digest = hashlib.sha256()
        with temporary.open("rb") as downloaded:
            for chunk in iter(lambda: downloaded.read(64 * 1024), b""):
                digest.update(chunk)

        if digest.hexdigest() != expected_checksum.lower():
            print("Download failed: checksum did not match.")
            return

        try:
            if os.name == "nt":
                os.rename(temporary, target)
            else:
                os.link(temporary, target)
        except OSError as exc:
            print(f"Could not save the finished download: {exc}")
            return

        print(f"Downloaded to {target}")
    finally:
        temporary.unlink(missing_ok=True)


def client_directory(client, reader):
    send_message(client, "DIR")
    status, message = read_status(reader)
    if status == "LIST":
        names = json.loads(message)
        print("\n".join(names) if names else "The folder is empty.")
    else:
        print(message)


def run_file_command(client, reader, cmd, argument):
    """Return False for non-file commands so the original loop handles them."""
    if cmd == "SUBFOLDER":
        action, _, path = argument.partition(" ")
        if action.lower() not in {"create", "delete"} or not path:
            print("Usage: SUBFOLDER create|delete folder")
            return True
        cmd, argument = "SUBFOLDER_" + action.upper(), path.lstrip()

    handlers = {"UPLOAD": client_upload, "DOWNLOAD": client_download}
    if cmd == "DIR":
        client_directory(client, reader)
    elif cmd in handlers:
        if argument:
            handlers[cmd](client, reader, argument)
        else:
            print(f"Usage: {cmd} filename")
    elif cmd in {"DELETE", "SUBFOLDER_CREATE", "SUBFOLDER_DELETE"}:
        if not argument:
            print(f"Usage: {cmd} path")
        else:
            send_message(client, f"{cmd}@{argument}")
            print(read_status(reader)[1])
    else:
        return False
    return True
