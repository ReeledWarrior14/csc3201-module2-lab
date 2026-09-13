from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



def pad(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding


# Generate key and IV
key = get_random_bytes(16)
iv = get_random_bytes(16)


def ECB_encrypt(contents, key):
    total = b''
    cipher = AES.new(key, AES.MODE_ECB)
    # separate into 128 bit blocks
    while len(contents) > 0:
        block = contents[:16]
        contents = contents[16:]
        ciphertext = cipher.encrypt(block)
        total += ciphertext

    return total


def CBC_encrypt(contents, key, iv):
    total = b''
    # separate into 128 bit blocks
    while len(contents) > 0:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        block = contents[:16]
        contents = contents[16:]
        ciphertext = cipher.encrypt(block)
        total += ciphertext
        iv = ciphertext  # Update IV to the last ciphertext block for CBC mode

    return total


def prepare_message(message):
    # url encode
    message = message.replace(";", "%3B").replace("=", "%3D")
    
    message = "userid=456;userdata=" + message + ";session-id=31337"

    return message

def submit(message, key, iv):
    message = prepare_message(message)

    print("Prepared message: " + message)

    message = message.encode('ascii')

    message = pad(message)

    return CBC_encrypt(message, key, iv)


def verify(encrypted, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted)
    decrypted = decrypted.decode('ascii', errors='replace')

    print("Decrypted message: " + decrypted)

    if "admin=true" in decrypted:
        return True
    else:
        return False


# message = input("Enter a message to encrypt: ")
message = "admin/true"

# Find position of '/' in the final message after url encoding and other stuff
slash_pos = prepare_message(message).index('/')

encrypted = submit(message, key, iv)

print("Encrypted message (hex): " + ''.join([hex(x)[2:].zfill(2) for x in encrypted]))

# Calculate which block needs modification
block_num = (slash_pos // 16)  # Block containing the target byte
pos_in_prev_block = slash_pos % 16
prev_block_start = (block_num - 1) * 16  # Start of previous block

# XOR the byte in previous block
modified_ciphertext = bytearray(encrypted)
modified_ciphertext[prev_block_start + pos_in_prev_block] ^= (ord('/') ^ ord('='))

print("Modified message  (hex): " + ''.join([hex(x)[2:].zfill(2) for x in modified_ciphertext]))

print("is admin: " + str(verify(bytes(modified_ciphertext), key, iv)))
