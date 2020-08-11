from cbc_encrypt import baddecrypt
from Crypto.Util.Padding import pad, unpad
import base64
import requests


def decryptblock(block1, block2):
    solve = bytearray(16)
    for j in range(15,-1,-1):    
        for i in range(256):
            iv = constructIV(i,j, solve, block1)
            payload = base64.b64encode(iv+block2)
            if trydecrypt(payload):
                pad = bytearray((16-j).to_bytes(1, 'big'))
                ivsmall = bytearray((i).to_bytes(1, 'big'))
                ptext = bytearray(bxor3(pad, ivsmall, block1[j:j+1]))
                solve[j:j+1] = ptext
                print(str(solve)[12:-2])
                break
            if i == 255:
                raise Exception
    return solve

def decrypt(s):
    shex = bytearray(base64.b64decode(s))
    N = len(shex)//16
    solution = bytearray()
    for i in range(N-1):
        block1 = shex[16*i:16*(i+1)]
        block2 = shex[16*(i+1):16*(i+2)]
        solution = solution + decryptblock(block1, block2)
    print("\n\n\n~~~~~~~~~    COMPLETE   ~~~~~~~~~~\n\n\n")
    print("Decrypted to: " + str(solution)[12:-2])
    return solution

def encryptblock(block2, ptextblock):
    block1 = bytearray(16)
    for j in range(15,-1,-1):    
        for i in range(256):
            iv = constructIV(i,j, block1, ptextblock)
            payload = base64.b64encode(iv+block2)
            if trydecrypt(payload):
                pad = bytearray((16-j).to_bytes(1, 'big'))
                ivsmall = bytearray((i).to_bytes(1, 'big'))
                block1[j:j+1] = bytearray(bxor3(pad, ivsmall, ptextblock[j:j+1]))
                print(str(block1)[12:-2])
                break
            if i == 255:
                raise Exception
    return block1

def encrypt(s, barray=False):
    if barray:
        shex = bytearray(s)
        print(shex)
    else:
        shex = bytearray(pad(s.encode(),16))
    N = len(shex)//16
    solution = bytearray(16)
    block2 = bytearray(16)
    for i in range(N-1, -1, -1):
        block2 = encryptblock(block2, shex[16*i:16*(i+1)])
        solution = block2 + solution
    solution = base64.b64encode(solution)
    print("\n\n\n~~~~~~~~~    COMPLETE   ~~~~~~~~~~\n\n\n")
    print("Encrypted to: " + str(solution))
    return solution

#This needs to be specialized
def trydecrypt(c1, test=False):
    return baddecrypt(c1, test)

def constructIV(i, j, p, c):
    iv = bytearray((i).to_bytes(j+1, 'big'))
    if j == 15:
        return iv
    for k in range(15-j):
        p1 = bytearray((16-j).to_bytes(1, 'big'))
        p2 = p[j+k+1:j+k+2]
        c1 = c[j+k+1:j+k+2]
        iv = iv + bytearray(bxor3(p1, p2, c1))
    return iv
    
def bxor3(b1, b2, b3):
    t = bytearray(bxor(b1, b2))
    return bxor(t, b3)
    
def bxor(b1, b2):
    return bytes([a ^ b for a, b in zip(b1,b2)])
