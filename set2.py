from utils import *
from aes import *

CHAL12_SECRET_KEY = random_aes_key()
CHAL12_SECRET = base64_to_bytes("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
CHAL14_RANDOM_BYTES = random_bits(random_int(1,15))


def encryption_oracle(to_encrypt):
    key = random_aes_key()

    before = random_bits(random_int(5,10))
    after = random_bits(random_int(5,10))

    to_encrypt = pkcs7pad(before + to_encrypt + after,16)
    

    if(random_int(0,1) == 0):
        ciphertext = aes_ecb_encrypt(key, to_encrypt)
    else:
        ciphertext = aes_cbc_encrypt(key, to_encrypt, random_aes_key())

    return ciphertext


def chal12_oracle(to_encrypt):
    to_append = CHAL12_SECRET
    to_encrypt += to_append
    to_encrypt = pkcs7pad(to_encrypt, 16)

    ciphertext = aes_ecb_encrypt(CHAL12_SECRET_KEY, to_encrypt)

    return ciphertext

def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return "email={}&uid=10&role=user".format(email)


def parse_profile(to_parse):
    pairs = to_parse.split("&")
    s = {}
    for pair in pairs:
        name = pair.split("=")[0]
        val = pair.split("=")[1]
        s[name] = val
    return s


def chal13_oracle(email, key):
    profile = profile_for(email)
    return aes_ecb_encrypt(key, pkcs7pad(bytes(profile, 'utf-8'), 16))

def chal14_oracle(to_encrypt):
    to_append = CHAL12_SECRET
    to_encrypt =  CHAL14_RANDOM_BYTES + to_encrypt + to_append
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
    chosen_plaintext = b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

    for _ in range(0,10):
        ciphertext = encryption_oracle(chosen_plaintext)

        if ciphertext[16:32] == ciphertext[32:48]:
            #print("Detected ECB")
            a = True
        else:
            a = True
            #print("Detected CBC")

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

    ciphertext = chal12_oracle(b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    if ciphertext[16:32] == ciphertext[32:48]:
        #print("Detected ECB")
        a = True
    
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
                
def challenge13(): 
    key = random_aes_key() #this is unknown

    admin = pkcs7pad(bytes("admin", 'utf-8'), 16).decode("utf-8")

    #find admin block 
    admin_block = b''
    for x in range(0,16):
        payload = ("A" * x ) + admin + admin                
        ciphertext = chal13_oracle("foo" + payload + "@gmail.com", key)
        blocks = [ciphertext[i : i + 16] for i in range(0, len(ciphertext), 16)]
        
        for i in range(0,len(blocks)):
            for j in range(0, len(blocks)):
                if i == j:
                    continue
                if blocks[i] == blocks[j]:
                    admin_block = blocks[i]
                    break
        if admin_block != b'':
            break

    ciphertext = chal13_oracle("foo@gmail.com", key)
    ciphertext = ciphertext[0:-16]
    ciphertext += admin_block
    
    plaintext = aes_ecb_decrypt(key, ciphertext)
    x = parse_profile(pkcs7unpad(plaintext).decode("utf-8"))
    challenge_complete(13, x, parse_profile("email=foo@gmail.com&uid=10&role=admin"))

def challenge14():
        

    #first find the block size
    block_size = 0
    found = False
    counter = 1
    prev_bsize = len(chal14_oracle(b''))
    
    while(found == False):
        curr_bsize = len(chal14_oracle(b'A' * counter))
        if prev_bsize != curr_bsize:
            block_size = curr_bsize - prev_bsize
            found = True
        counter += 1

    #find the number of bytes being added...
    test_bytes = b'A' * block_size * 2 # 16 * 2
    to_add = -1
    appended_size = -1
    for i in range(0, block_size):
        
        ciphertext = chal14_oracle(b'X' * i + test_bytes)

        if ciphertext[block_size:block_size*2] == ciphertext[block_size * 2: block_size * 3]:
            to_add = i
            appended_size = block_size - i

    blocks_count = len(ciphertext) // block_size
    

    secret = b''
    for block_number in range(0, blocks_count): 
        start = (to_add + appended_size) + (block_number * block_size)
        end = (to_add + appended_size) + (block_number * block_size) + block_size


        for x in range(1, block_size + 1):
            short_input = (b'X' * to_add) + (b'A' * (block_size - x))         
            encrypted_short_input = chal14_oracle(short_input)[start:end] 

            #check against dictionary
            base = (b'X' * to_add) + (b'A' * (block_size - x)) + secret
            for i in range(0,255):
                
                block_of_interest = chal14_oracle(base + bytes([i]))[start:end] 

                if block_of_interest == encrypted_short_input:
                    secret += bytes([i])
                    break
            
            # break
    challenge_complete(14, pkcs7unpad(secret), CHAL12_SECRET)

def challenge15():
    assert pkcs7unpad(b'ICE ICE BABY\x04\x04\x04\x04') == b'ICE ICE BABY' 

    assert validpkcs7(b'ICE ICE BABY\x05\x05\x05\x05') == False
    assert validpkcs7(b'ICE ICE BABY\x01\x02\x03\x04') == False

    challenge_complete(15, True, True)



challenge9()
challenge10()
challenge11()
challenge12()
challenge13()
challenge14()
challenge15()