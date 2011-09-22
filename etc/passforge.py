#!/usr/bin/env python
import base64
import math
import sys
from pbkdf2 import PBKDF2

def b64encode(text):
    """Base64 encoding with -_ instead of +/"""
    return base64.b64encode(text, '-_')

def generate(password, salt, iterations, length=16):
    byte_len = int(math.ceil(length * 3 / 4.))
    return b64encode(PBKDF2(password, salt, iterations).read(byte_len))

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print 'passforge.py PASSWORD SALT ITERATIONS [LENGTH]'
        sys.exit(1)

    if len(sys.argv) > 4:
        length = sys.argv[4]
    else:
        length = 16
    print generate(sys.argv[1], sys.argv[2], int(sys.argv[3]), length)

