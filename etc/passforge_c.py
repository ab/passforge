#!/usr/bin/env python
import base64
import os.path
import sys
from subprocess import Popen, PIPE

def b64encode(text):
    """Base64 encoding with -_ instead of +/"""
    return base64.b64encode(text, '-_')

def hex_to_b64(hexdata):
    # pad input
    if len(hexdata) % 2 != 0:
        hexdata += '0'

    chars = []
    for i in range(len(hexdata) // 2):
        byte = hexdata[i*2:i*2+2]
        chars.append(chr(int(byte, 16)))

    return b64encode(''.join(chars))

def str_to_hex(string):
    return ''.join(hex(ord(c))[2:] for c in string)

def generate(password, salt, iterations, length=16):
    path = os.path.abspath(os.path.dirname(sys.argv[0]))
    cmd = os.path.join(path, 'pbkdf2')
    if not os.path.exists(cmd):
        print 'command does not exist:', cmd
    p = Popen([cmd, str_to_hex(salt), iterations], stdin=PIPE, stdout=PIPE)
    out, err = p.communicate(password)

    key = hex_to_b64(out.strip())

    return key[:length]

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print 'passforge_c.py PASSWORD SALT ITERATIONS'
        sys.exit(1)

    assert(int(sys.argv[3]))

    try:
        length = int(sys.argv[4])
    except IndexError:
        length = 12

    print generate(sys.argv[1], sys.argv[2], sys.argv[3], length)
