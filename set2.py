from utils import *
from aes import *

CHAL12_SECRET_KEY = random_aes_key()
CHAL12_SECRET = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

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


def chal12_oracle(to_encrypt):
    to_append = CHAL12_SECRET
    to_encrypt += to_append
    to_encrypt = pkcs7pad(to_encrypt, 16)

    ciphertext = aes_ecb_encrypt(CHAL12_SECRET_KEY, to_encrypt)

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

def challenge12():
    #first find cipher block size
    block_size = 0
    found = False
    counter = 1
    prev_bsize = len(chal12_oracle(b''))
    blocks = prev_bsize // 16

    while(found == False):
        curr_bsize = len(chal12_oracle(b'A' * counter))
        if prev_bsize != curr_bsize:
            block_size = curr_bsize - prev_bsize
            found = True
        counter += 1
    print(block_size)

    ciphertext = chal12_oracle(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    if ciphertext[16:32] == ciphertext[32:48]:
        print("Detected ECB")

    
    secret = b''
    for block_number in range(0, blocks): 
        for x in range(1, block_size + 1):
            short_input = b'A' * (block_size - x)            
            
            start = (block_number * block_size)
            end = (block_number * block_size) + block_size

            encrypted_short_input = chal12_oracle(short_input)[start:end] 
            
            #check against dictionary
            base = b'A' * (block_size - x) + secret

            for i in range(0,255):
                
                block_of_interest = chal12_oracle(base + bytes([i]))[start:end] 

                if block_of_interest == encrypted_short_input:
                    secret += bytes([i])
                    break
    challenge_complete(12, pkcs7unpad(secret), CHAL12_SECRET)
            
        
        

       

#challenge9()
#challenge10()
#challenge11()
challenge12()