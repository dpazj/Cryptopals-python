


def score_plaintext(plaintext):
    eta = b"etaoin"
    shr = b"shrdlu"
   
    score = 0
    for x in plaintext:
        if x in eta:
            score += 3
        elif x in shr:
            score += 2
        elif (x >= 65 and x <= 90) or (x >= 97 and x <= 122):
            score += 1
        else:
            score += -1
    return score


def hamming_distance(a, b):
    count = 0
    for x,y in zip(a,b):
        z = x ^ y
        while(z):
            count += 1
            z &= z -1
    return count
    