#!/usr/bin/env python
import math
import sys
from base64 import b64encode
from pbkdf2 import PBKDF2

def generate(password, salt, iterations, length=16):
    byte_len = int(math.ceil(length * 3 / 4.))
    encoded = b64encode(PBKDF2(password, salt, iterations).read(byte_len))
    return encoded[:length]

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print 'passforge.py PASSWORD SALT ITERATIONS [LENGTH]'
        sys.exit(1)

    if len(sys.argv) > 4:
        length = int(sys.argv[4])
    else:
        length = 16
    print generate(sys.argv[1], sys.argv[2], int(sys.argv[3]), length)

