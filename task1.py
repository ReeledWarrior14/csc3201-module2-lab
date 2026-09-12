from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



def pad(message):
    padding_length = 16 - (len(message) % 16)
    padding = bytes([padding_length] * padding_length)
    return message + padding

filename = "images/mustang.bmp"

def read_bmp_header_and_contents(filename):
    with open(filename, 'rb') as f:
        header = f.read(54)  # BMP header is 54 bytes
        contents = f.read()

    return header, contents

# Generate key and IV
key = get_random_bytes(16)
iv = get_random_bytes(16)

header, contents = read_bmp_header_and_contents(filename)

contents = pad(contents)

def EBC_encrypt(contents, key):
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

encrypted = EBC_encrypt(contents, key)
with open("images/mustang_EBC_encrypted.bmp", 'wb') as f:
    f.write(header)
    f.write(encrypted)

encrypted = CBC_encrypt(contents, key, iv)
with open("images/mustang_CBC_encrypted.bmp", 'wb') as f:
    f.write(header)
    f.write(encrypted)
