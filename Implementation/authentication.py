#Final Version
import hashlib
import hmac
import os
import secrets


# Temporary user storage
# Eventually this will be replaced with a database

# Hash the password using a salt, so the original password doesn't need to be stored
def hash_password(password, salt):
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200000
    )


# Create an account with its own salt and permission level
def create_user(password, level):
    salt = os.urandom(16) # Random salt for each user

    return {
        "password": hash_password(password, salt),
        "salt": salt,
        "level": level
    }


# Accounts used for testing the server
USERS = {
    "admin": create_user("secret123", "admin"),
    "user1": create_user("password123", "user")
}


# Check a username and password against the stored account information
def authenticate(username, password):

    if username not in USERS:
        return False

    user = USERS[username]

    password_hash = hash_password(password, user["salt"])

    # Compare the hashes instead of the actual passwords
    return hmac.compare_digest(password_hash, user["password"])


# Get the account type, which determines what commands they can use
def get_access_level(username):

    if username in USERS:
        return USERS[username]["level"]

    return None


### Check which commands each account type is allowed to use
def has_permission(level, command):

    # Admin has access to all of the file commands
    if level == "admin":
        return command in [
            "TASK", "DIR", "UPLOAD", "DOWNLOAD",
            "DELETE", "SUBFOLDER_CREATE", "SUBFOLDER_DELETE"
        ]

    # Regular users cannot delete files or folders
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

    # Use the same hashing method as the server
    key = hash_password(password, salt)

    # Combine the key with the challenge to prove the client knows the password
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

    # Generate the expected response using the stored password hash
    expected = hmac.new(
        user["password"],
        challenge.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()

    # If both responses match, the client provided the correct password
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
