#!/usr/bin/env python

import sys
import logging
import getpass
import paramiko


HOST='127.0.0.1'
PORT=22
CMD='uname -a && uptime'


if len(sys.argv) == 1:
    print 'usage: %s [host [port [cmd1 cmd2 cmdN]]]' % (sys.argv[0])
if len(sys.argv) > 1:
    HOST=str(sys.argv[1])
if len(sys.argv) > 2:
    PORT=int(sys.argv[2])
if len(sys.argv) > 3:
    CMD = ' '.join(sys.argv[3:])

root = logging.getLogger()
root.setLevel(logging.DEBUG)
ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)

usern = getpass.getpass('User: ')
passw = getpass.getpass('Pass: ')

try:
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy( paramiko.AutoAddPolicy() )
    print 'Connecting to %s:%d as %s' % (HOST, PORT, usern)
    ssh.connect(HOST, port=PORT, username=usern, password=passw)
    ssh.get_transport().set_hexdump(True)

    print ('#'*32) + ' COMMAND: ' + str(CMD)
    stdin, stdout, stderr =  ssh.exec_command(CMD)
    print '#'*32
    print str(stderr.read())
    print str(stdout.read())
finally:
    ssh.close()
