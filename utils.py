from base64 import b64decode, b64encode


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




