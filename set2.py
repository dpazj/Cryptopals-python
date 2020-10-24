from utils import *
from aes import *


def encryption_oracle(to_encrypt):
    key = random_aes_key()

    before = random_bits(random_int(5,10))
    after = random_bits(random_int(5,10))

    to_encrypt = pkcs7pad(before + to_encrypt + after,16)
    

    if(random_int(0,1) == 0):
        print("Encrypting ECB...")
        ciphertext = aes_ecb_encrypt(key, to_encrypt)
    else:
        print("Encrypting CBC...")
        ciphertext = aes_cbc_encrypt(key, to_encrypt, random_aes_key())

    return ciphertext


def challenge9():
    a = b"YELLOW SUBMARINE"  
    challenge_complete(9, pkcs7pad(a, 20), b"YELLOW SUBMARINE\x04\x04\x04\x04")

def challenge10():
    with open("10.txt") as f:
        lines = f.read().splitlines()
    content = ''
    for line in lines:
        content += line

    key = b"YELLOW SUBMARINE"
    iv = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ciphertext = base64_to_bytes(content)

    challenge_complete(10, aes_cbc_encrypt(key, aes_cbc_decrypt(key, ciphertext, iv), iv), ciphertext)

def challenge11():
    print(random_int(5,10))
    chosen_plaintext = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    for _ in range(0,10):
        ciphertext = encryption_oracle(chosen_plaintext)

        if ciphertext[16:32] == ciphertext[32:48]:
            print("Detected ECB")
        else:
            print("Detected CBC")

    challenge_complete(11, "A", "A")   







#challenge9()
#challenge10()
challenge11()