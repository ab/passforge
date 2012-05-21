#!/usr/bin/env python
import optparse
import sys
from datetime import datetime
from getpass import getpass

import bcrypt

SALT_PADDING = 'passforgepassfor'
SALT_LENGTH = 16

LEVEL_MAP = {'very low': 12,
             'low': 13,
             'medium': 14,
             'high': 15,
             'very high': 16}

class PassForgeError(Exception):
    pass

def pad_salt(salt):
    """Pad salt to SALT_LENGTH characters using SALT_PADDING."""
    return salt + SALT_PADDING[:SALT_LENGTH-len(salt)]

def generate(password, salt, log_rounds, length=16):
    salt = pad_salt(salt)
    bsalt = bcrypt.encode_salt(salt, log_rounds)
    hashed = bcrypt.hashpw(password, bsalt)

    derived = hashed[len(bsalt):]

    if len(derived) < length:
        raise PassForgeError('maximum generated length is %d' % len(derived))
    if length < 0:
        raise PassForgeError('minimum generated length is 0')

    return derived[:length]

class PassForge(object):
    def __init__(self, opts, interactive=True):
        self.opts = opts
        self.interactive = interactive
        self.iterations = opts.iterations
        self.length = opts.length
        self.nickname = opts.nickname

        self.verbose = opts.verbose

        self.password = None
        if opts.pass_file:
            if opts.pass_file == '-':
                f = sys.stdin
            else:
                f = open(opts.pass_file, 'r')

            self.vprint('reading password from first line of %s' % f.name)
            self.password = f.readline().rstrip('\r\n')

        if opts.strengthening:
            try:
                self.iterations = LEVEL_MAP[opts.strengthening]
            except KeyError:
                print 'Valid strengthening levels:', LEVEL_MAP
                raise PassForgeError('Invalid strengthening level')

        if interactive:
            if not self.iterations:
                self.iterations = int(raw_input('iterations: '))

            if not opts.pass_file:
                self.password = getpass('master password: ')

            if not self.length:
                self.length = 14

        else:
            if not self.password:
                raise PassForgeError('Must provide password file')

            if not self.iterations:
                raise PassForgeError('Must provide iterations / strengthening')

            if not self.nickname:
                raise PassForgeError('Must provide nickname')

            if not self.length:
                raise PassForgeError('Must provide length')

        if not self.password:
            raise PassForgeError('password is empty')

    def vprint(self, message):
        if self.verbose:
            sys.stderr.write(message + '\n')

    def pwgen(self, nickname):
        start = datetime.now()

        key = generate(self.password, nickname, self.iterations, self.length)

        elapsed = datetime.now() - start
        secs = elapsed.seconds + elapsed.microseconds / 1000000.
        self.vprint('generated in %.2f seconds' % secs)
        return key

    def run_interactive(self):
        if self.nickname:
            print self.pwgen(self.nickname)
            return

        while True:
            nickname = raw_input('nickname: ')
            if not nickname:
                break

            print self.pwgen(nickname)

    def run_batch(self):
        print self.pwgen(self.nickname)

    def run(self):
        if self.interactive:
            self.run_interactive()
        else:
            self.run_batch()

if __name__ == '__main__':
    p = optparse.OptionParser()

    p.usage = '%prog [options]\n' + \
              'options not given will be prompted interactively'

    p.add_option('-p', '--password-file', dest='pass_file', metavar='FILE',
                 help='read master password from FILE')
    p.add_option('-n', '--nickname', dest='nickname', metavar='TEXT',
                 help='per-site nickname used to determine unique password')
    p.add_option('-i', '--iterations', dest='iterations', metavar='NUM',
                 type='int', help='number of PBKDF2 iterations')
    p.add_option('-s', '--strengthening', dest='strengthening',
                 metavar='LEVEL', help='number of iterations by description',
                 choices=list(LEVEL_MAP.keys()))
    p.add_option('-l', '--length', dest='length', metavar='LENGTH',
                 type='int', help='length of generated password')
    p.add_option('-b', '--batch', dest='batch', action='store_true',
                 help="non-interactive mode")

    p.add_option('-q', '--quiet', dest='verbose', action='store_false',
                 default=True, help='be less verbose')

    opts, args = p.parse_args()

    interactive = not opts.batch

    try:
        pf = PassForge(opts, interactive)
        pf.run()
    except PassForgeError, e:
        sys.stderr.write('ERROR: ' + e.args[0] + '\n')
        sys.exit(3)
    except (KeyboardInterrupt, EOFError):
        print ''

