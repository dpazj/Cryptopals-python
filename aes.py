from Crypto.Cipher import AES
from utils import *
import os

AES_BLOCK_SIZE = 16

def random_aes_key():
    return os.urandom(16)

def aes_cbc_encrypt(key, plaintext, iv):
    if (len(plaintext) % AES_BLOCK_SIZE) != 0:
        raise Exception("Plaintext length must be divisible by {}!".format(AES_BLOCK_SIZE))
    if(len(iv) != 16):
        raise Exception("IV must be 16 bytes")

    aes = AES.new(key, AES.MODE_ECB)
    
    ciphertext = bytearray()
    prev_cipher_block = iv
    for i in range(0, len(plaintext), AES_BLOCK_SIZE):
        block = plaintext[i:i+AES_BLOCK_SIZE]
        block = xor_util(block, prev_cipher_block)
        prev_cipher_block = aes.encrypt(block)
        ciphertext += prev_cipher_block

    return ciphertext


def aes_cbc_decrypt(key, ciphertext, iv):
    if (len(ciphertext) % AES_BLOCK_SIZE) != 0:
        raise Exception("Plaintext length must be divisible by {}!".format(AES_BLOCK_SIZE))
    if(len(iv) != 16):
        raise Exception("IV must be 16 bytes")

    aes = AES.new(key, AES.MODE_ECB)
    plaintext = bytearray()

    prev_cipher_block = iv
    for i in range(0, len(ciphertext), AES_BLOCK_SIZE):
        block = ciphertext[i:i+AES_BLOCK_SIZE]
        plaintext_block = aes.decrypt(block)
        plaintext_block = xor_util(plaintext_block, prev_cipher_block)
        prev_cipher_block = block        
        plaintext += plaintext_block

    return plaintext

def aes_ecb_encrypt(key, plaintext):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.encrypt(plaintext)

def aes_ecb_decrypt(key, ciphertext):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(ciphertext)

