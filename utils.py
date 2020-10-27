from base64 import b64decode, b64encode
import os, random

def random_bits(bits):
    return os.urandom(bits)

def random_int(a, b):
    return random.SystemRandom().randint(a, b)

def challenge_complete(chall, ans, expected):
    assert ans == expected, "Challenge {}:\n Got\t\t{}\n Expected\t{}".format(chall, ans, expected)
    print("Challenge {} complete".format(chall))
    
def hex_to_base64(hex):
    return bytes_to_base64(hex_to_bytes(hex))

def hex_to_bytes(hex):
    return bytes.fromhex(hex)

def bytes_to_hex(byte_ar):
    return byte_ar.hex()

def bytes_to_base64(bytes_ar):
    return b64encode(bytes_ar).decode()

def base64_to_bytes(base64):
    return b64decode(base64)

def pkcs7pad(to_pad, block_length):
    if block_length > 255:
        raise Exception("Block length must be equal to or less than 255!")

    bytes_required = block_length - (len(to_pad) % block_length)

    for i in range(0, bytes_required):
        to_pad += bytes([bytes_required])
    
    return to_pad

def validpkcs7(to_unpad):
    last_byte = to_unpad[-1:]
    last_byte_int = int.from_bytes(last_byte, "big")
    return to_unpad[-last_byte_int: ] == last_byte * last_byte_int


def pkcs7unpad(to_unpad):
    if not validpkcs7(to_unpad):
        assert("invalid pkcs7 padding")
    last_byte = int.from_bytes(to_unpad[-1:],"big")
    return to_unpad[:-last_byte]


def xor_util(plaintext, key):
    cipher = bytearray(len(plaintext))
    for i in range(0, len(plaintext)):
        cipher[i] = plaintext[i] ^ key[i % len(key)]
    return cipher


    






