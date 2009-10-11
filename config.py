import os

rcfile = os.path.join(os.getenv('HOME'), '.quileecherc')

rc = dict(map(lambda x : map(str.strip, x.split('=')), open(rcfile).readlines()))

hostname = rc.has_key('hostname') and rc['hostname'] or socket.hostname()

ssh_no_users = set(rc.has_key('ssh_no_users') and rc['ssh_no_users'].split(',') or [])

default_filters = rc.has_key('default_filters') and rc['default_filters'].split(',') or []

print "Using hostname <", hostname, ">"

import socket
hostip = socket.gethostbyname(hostname)

