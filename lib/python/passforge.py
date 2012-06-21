#!/usr/bin/env python
import optparse
import sys
from datetime import datetime
from getpass import getpass

import bcrypt

SALT_LENGTH = 16

LEVEL_MAP = {'very low': 12,
             'low': 13,
             'medium': 14,
             'high': 15,
             'very high': 16}

DEBUG = False

try:
    from hashlib import sha1
except ImportError:
    from sha import sha as sha1

class PassForgeError(Exception):
    pass

def salt_from_nickname(nick):
    """
    Create a suitable salt from the user-supplied nickname.

    We are using truncated SHA1, but note that the cryptographic properties of
    this function are actually not important. All we care about is that the
    output length be SALT_LENGTH and that the output be unlikely to collide
    with other commonly used nicknames.
    """
    digest = sha1(nick).digest()
    assert len(digest) >= SALT_LENGTH
    return digest[:SALT_LENGTH]

def generate(password, nickname, log_rounds, length=16):
    salt = salt_from_nickname(nickname)
    bsalt = bcrypt.encode_salt(salt, log_rounds)
    if DEBUG: print 'bcrypt salt:', bsalt

    hashed = bcrypt.hashpw(password, bsalt)
    if DEBUG: print 'hashed:', hashed

    derived = hashed[len(bsalt):]

    if len(derived) < length:
        raise PassForgeError('maximum generated length is %d' % len(derived))
    if length < 0:
        raise PassForgeError('minimum generated length is 0')

    return derived[:length]

class Generator(object):
    def __init__(self, opts):
        self.opts = opts
        self.interactive = opts.interactive
        self.rounds = opts.rounds
        self.length = opts.length
        self.nickname = opts.nickname

        self.verbose = opts.verbose

        self.password = None

        if opts.strengthening:
            try:
                self.rounds = LEVEL_MAP[opts.strengthening]
            except KeyError:
                print 'Valid strengthening levels:', LEVEL_MAP
                raise PassForgeError('Invalid strengthening level')

        if self.interactive:
            if not self.rounds:
                self.rounds = int(raw_input('rounds: '))

            if not opts.pass_file:
                self.password = getpass('master password: ')

            if not self.length:
                self.length = 14

        else:
            if not opts.pass_file:
                raise PassForgeError('Must provide password file')

            if not self.rounds:
                raise PassForgeError('Must provide rounds / strengthening')

            if not self.nickname:
                raise PassForgeError('Must provide nickname')

            if not self.length:
                raise PassForgeError('Must provide length')

        if opts.pass_file:
            if opts.pass_file == '-':
                f = sys.stdin
                self.vprint('reading password from first line of STDIN')
            else:
                f = open(opts.pass_file, 'r')
                self.vprint('reading password from first line of %r' % f.name)

            self.password = f.readline().rstrip('\r\n')

        if not self.password:
            raise PassForgeError('password is empty')

    def vprint(self, message):
        if self.verbose:
            sys.stderr.write(message + '\n')

    def pwgen(self, nickname):
        start = datetime.now()

        key = generate(self.password, nickname, self.rounds, self.length)

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
              'Options not given will be prompted interactively.'

    p.add_option('-p', '--password-file', dest='pass_file', metavar='FILE',
                 help='read master password from FILE')
    p.add_option('-n', '--nickname', dest='nickname', metavar='TEXT',
                 help='per-site nickname used to determine unique password')
    p.add_option('-r', '--rounds', dest='rounds', metavar='NUM',
                 type='int', help='number of bcrypt log rounds')
    p.add_option('-s', '--strengthening', dest='strengthening',
                 metavar='LEVEL', help='number of log rounds by description',
                 choices=list(LEVEL_MAP.keys()))
    p.add_option('-l', '--length', dest='length', metavar='LENGTH',
                 type='int', help='length of generated password')
    p.add_option('-b', '--batch', dest='interactive', action='store_false',
                 default=True, help="non-interactive mode")

    p.add_option('-q', '--quiet', dest='verbose', action='store_false',
                 default=True, help='be less verbose')
    p.add_option('-d', '--debug', dest='debug', action='store_true',
                 default=False, help='enable debug mode')

    opts, args = p.parse_args()

    if opts.debug:
        DEBUG = True

    try:
        g = Generator(opts)
        g.run()
    except PassForgeError, e:
        sys.stderr.write('ERROR: ' + e.args[0] + '\n')
        sys.exit(3)
    except (KeyboardInterrupt, EOFError):
        print ''

