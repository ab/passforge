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

def error(message):
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

def get_user(name):
    rows = c.execute('select * from salts where user=%s', name) > 0
    if rows:
        return c.fetchone()
    else:
        return None

# POST/GET parameters
form = cgi.FieldStorage()
if 'action' not in form:
    error('Valid actions: get, create')

if form['action'].value == 'get':
    if 'user' not in form:
        error('Must provide user.')

    user = get_user(form['user'].value)
    if not user:
        error('No such user.')

    json_return({'salt': user['salt']})

elif form['action'].value == 'create':
    if 'user' not in form:
        error('Must provide user.')

    username = form['user'].value

    if get_user(username):
        error('Username already taken.')

    if 'salt' in form:
        salt = form['salt'].value
    else:
        salt = base64.b64encode(os.urandom(config.salt_bytes))

    query = 'insert into salts (`user`, `salt`) VALUES (%s, %s)'
    c.execute(query, (username, salt))

    json_return({'salt': salt})

content_type('text/plain')

c.execute('select * from salts');
data = c.fetchall()
print data
print data[0]['salt']
print 'foo'
