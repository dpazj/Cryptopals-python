from utils import *
from set1_utils import * 




def challenge1():
    base64 = hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    print(b)

    challenge_complete(1, base64,  "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")

def challenge2():
    a = hex_to_bytes("1c0111001f010100061a024b53535009181c")
    b = hex_to_bytes("686974207468652062756c6c277320657965")

    ans = bytearray(len(a)) 

    for i in range(0, len(a)):
        ans[i] = a[i] ^ b[i]

    ans = ans.hex()
    
    challenge_complete(2, ans,  "746865206b696420646f6e277420706c6179")

def challenge3():
    a = hex_to_bytes("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

    top_score = 0
    best_ans = b""

    for i in range(0, 255):
        ans = bytearray(len(a))
        for j in range(0, len(a)):
            ans[j] = a[j] ^ i

        score = score_plaintext(ans)
        if score > top_score:
            best_ans = ans
            top_score = score
    challenge_complete(3,best_ans.decode("ascii"), "Cooking MC's like a pound of bacon")

def challenge4():
    with open('4.txt') as f:
        lines = f.readlines()

    top_score = 0
    best_ans = b""
    
    for line in lines:
        a = hex_to_bytes(line.strip())
        

        for i in range(0, 255):
            ans = bytearray(len(a))
            for j in range(0, len(a)):
                ans[j] = a[j] ^ i

            score = score_plaintext(ans)
            if score > top_score:
                best_ans = ans
                top_score = score

    challenge_complete(4, best_ans.decode("ascii"), "Now that the party is jumping\n")


def challenge5():
    a = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    ans = repeating_xor(a, key)
    challenge_complete(5, ans, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")

def challenge6():
    with open("6.txt") as f:
        lines = f.read().splitlines()
    content = ''
    for line in lines:
        content += line
  
  
    cipher = base64_to_bytes(content)
    

    return 1




challenge1()
# challenge2()
# challenge3()
# challenge4()
# challenge5()
challenge6()
