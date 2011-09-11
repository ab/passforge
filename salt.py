#!/usr/bin/env python
import cgi
import cgitb
cgitb.enable()

import base64
import os
import sys

import MySQLdb
import MySQLdb.cursors

try:
    import json
except ImportError:
    import simplejson as json

import config

# database parameters and initialization
db = MySQLdb.connect(config.host, config.user, config.passwd, config.db)
db.set_character_set('utf8')
c = db.cursor(MySQLdb.cursors.DictCursor)
del config.passwd

def content_type(ctype):
    print 'Content-Type: ' + ctype + '; charset=utf-8'
    print ''

def json_error(message):
    json_dump({'error': message, 'success': False})

def json_return(jdict):
    jdict['success'] = True
    json_dump(jdict)

def json_dump(data):
    content_type('application/json')
    print json.dumps(data)
    sys.exit(0)

def debug(data):
    content_type('text/plain')
    print data

class DoesNotExist(Exception):
    pass
class Error(Exception):
    pass

def get_user(name):
    rows = c.execute('select * from salts where user=%s', name) > 0
    if rows:
        return c.fetchone()
    else:
        raise DoesNotExist

def get_salt(username):
    user = get_user(username)
    return user['salt']

def gen_salt(length):
    return base64.b64encode(os.urandom(length))

def create_salt(username, salt=None):
    if not salt:
        salt = gen_salt(config.salt_bytes)

    query = 'insert into salts (`user`, `salt`) VALUES (%s, %s)'
    try:
        c.execute(query, (username, salt))
    except MySQLdb.IntegrityError, e:
        if e.args[0] == 1062:
            raise Error('Error getting/creating salt.')
        else:
            raise

    return salt

def get_or_create_salt(username):
    try:
        salt = get_salt(username)
    except DoesNotExist:
        salt = create_salt(username)
    return salt

def main():
    # POST/GET parameters
    form = cgi.FieldStorage()
    if 'action' not in form:
        raise Error('Valid actions: [get_create]')

    if form['action'].value == 'get_create':
        if 'user' not in form:
            raise Error('Must provide user.')

        salt = get_or_create_salt(form['user'].value)
        json_return({'salt': salt})


if __name__ == '__main__':
    try:
        main()
    except Error, e:
        json_error(e.args[0])
