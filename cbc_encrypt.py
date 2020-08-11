from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

key = b'\xcb\xd0X\xdc\xdac\x1c\xceyA\xd3b\xb0\xf2\xdaY\xcf\xbb\xff\x9e\xf7\x8f\xe5\xa8\xb4\xecc\xe3\x91&*B'

def encrypt(s):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(str.encode(s), AES.block_size))
    iv = cipher.iv
    c = base64.b64encode(iv+ciphertext)
    return c


def baddecrypt(c1, test=False):
    c = bytearray(base64.b64decode(c1))
    iv = c[:16]
    cdata = c[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    try:
        ptext = cipher.decrypt(cdata)
        if test:
            print(ptext)
        ptext1 = unpad(ptext, AES.block_size)
        return True
    except ValueError:
        return False
