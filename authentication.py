
import hashlib
import hmac
import os
import secrets


# Temporary user storage
# Eventually this will be replaced with a database

def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    )


def create_user(password, level):
    salt = os.urandom(16)

    return {
        "password": hash_password(password, salt),
        "salt": salt,
        "level": level
    }


USERS = {
    "admin": create_user("secret123", "admin"),
    "user1": create_user("password123", "user")
}


def authenticate(username, password):

    if username not in USERS:
        return False

    user = USERS[username]

    password_hash = hash_password(password, user["salt"])

    return hmac.compare_digest(password_hash, user["password"])


def get_access_level(username):

    if username in USERS:
        return USERS[username]["level"]

    return None


def has_permission(level, command):

    if level == "admin":
        return command in [
            "TASK", "DIR", "UPLOAD", "DOWNLOAD",
            "DELETE", "SUBFOLDER_CREATE", "SUBFOLDER_DELETE"
        ]

    elif level == "user":
        return command in [
            "TASK", "DIR", "UPLOAD", "DOWNLOAD",
            "SUBFOLDER_CREATE"
        ]

    return False


# Generate a random challenge for each login
def generate_challenge():
    return secrets.token_hex(32)


# Create the response using a password-derived key
def create_response(password, salt, challenge):

    key = hash_password(password, salt)

    response = hmac.new(
        key,
        challenge.encode("utf-8"),
        hashlib.sha256
    )

    return response.hexdigest()


# Verify the client's response
def verify_response(username, challenge, response):

    if username not in USERS:
        return False

    user = USERS[username]

    expected = hmac.new(
        user["password"],
        challenge.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(expected, response)



if __name__ == "__main__":
    

    '''
    # testing functions:
    print(authenticate("admin", "secret123"))
    print(authenticate("user1", "password123"))
    print(authenticate("admin", "wrongpassword"))
    print(get_access_level("admin"))
    print(get_access_level("user1"))

    # testing challenge-response authentication
    challenge = generate_challenge()

    salt = USERS["admin"]["salt"]

    response = create_response(
        "secret123",
        salt,
        challenge
    )

    print(verify_response("admin", challenge, response))
    print(verify_response("admin", challenge, "wrongresponse"))

    '''

    # V1 update test