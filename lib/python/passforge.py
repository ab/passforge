#!/usr/bin/env python
import math
import optparse
import sys
from base64 import b64encode
from datetime import datetime
from getpass import getpass
from pbkdf2 import PBKDF2

def generate(password, salt, iterations, length=16):
    byte_len = int(math.ceil(length * 3 / 4.))
    encoded = b64encode(PBKDF2(password, salt, iterations).read(byte_len))
    return encoded[:length]

LEVEL_MAP = {'low': 4096,
             'medium': 10000,
             'high': 25000,
             'very high': 100000}

class PassForgeError(Exception):
    pass

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

    def run_batch():
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
                 help='read password from FILE')
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

