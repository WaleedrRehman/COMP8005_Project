import ctypes
import sys
import secrets
import string

# Load libxcrypt
try:
    libcrypt = ctypes.CDLL("libcrypt.so")
except OSError:
    print("Error: libcrypt.so not found. Ensure libxcrypt is installed.")
    exit(1)

# Define function signature for `crypt()`
libcrypt.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
libcrypt.crypt.restype = ctypes.c_char_p

# Supported password hashing methods with correct salt formats
HASH_METHODS = {
    "yescrypt": "$y$j9T$",  # Yescrypt format
    "gost-yescrypt": "$gy$",  # GOST-Yescrypt
    "scrypt": "$7$",  # Scrypt
    "bcrypt": "$2b$12$",  # Bcrypt with cost factor 12
    "sha512crypt": "$6$",  # SHA-512
    "sha256crypt": "$5$",  # SHA-256
    "md5crypt": "$1$",  # MD5
}

# Function to generate random salts with the correct lengths
def generate_salt(method):
    """Generates a cryptographically secure salt of the appropriate length."""
    base64_chars = string.ascii_letters + string.digits + "./"

    if method in ["yescrypt", "gost-yescrypt", "scrypt", "sha512crypt", "sha256crypt", "sunmd5", "md5crypt"]:
        salt_length = 16  # Common for modern hash functions
    elif method in ["bcrypt", "bcrypt-a"]:
        salt_length = 22  # Bcrypt requires exactly 22 characters
    elif method == "bsdicrypt":
        salt_length = 8  # BSDiCrypt uses an 8-character salt
    elif method == "descrypt":
        salt_length = 2  # DEScrypt uses a 2-character salt
    elif method == "nt":
        return ""  # NT hash does not use a salt
    else:
        salt_length = 16  # Default fallback

    return "".join(secrets.choice(base64_chars) for _ in range(salt_length))

def is_method_supported(method, password, salt):
    """Check if a password hashing method is supported by libxcrypt."""
    try:
        hashed = libcrypt.crypt(password.encode(), salt.encode())
        return hashed is not None and hashed.decode() != "*0"  # Ensure it's a valid hash
    except Exception:
        return False

def hash_password(password, salt):
    """Hash a password using libxcrypt and the provided salt."""
    try:
        hashed = libcrypt.crypt(password.encode(), salt.encode())
        if hashed and hashed.decode() != "*0":
            return hashed.decode()
        else:
            return f"Error: crypt() returned *0 (unsupported method) for {salt}"
    except Exception as e:
        return f"Error: {e}"

def main():
    """Main function that takes a password from the command line and hashes using only supported methods."""
    if len(sys.argv) != 2:
        print("Usage: python3 hash_passwords.py <password>")
        exit(1)

    password = sys.argv[1]

    print(f"Checking supported hashing methods...\n")

    supported_methods = []
    for method, prefix in HASH_METHODS.items():
        salt = generate_salt(method)  # Generate random salt
        full_salt = prefix + salt  # Append generated salt to method prefix
        if is_method_supported(method, password, full_salt):
            supported_methods.append((method, full_salt))

    if not supported_methods:
        print("No supported hashing methods found.")
        exit(1)

    print(f"Supported hashing methods: {', '.join(method for method, _ in supported_methods)}\n")

    print(f"Hashing password '{password}' with supported methods...\n")
    for method, full_salt in supported_methods:
        hash_result = hash_password(password, full_salt)
        print(f"{method} ({full_salt}): {hash_result}")

if __name__ == "__main__":
    main()
