#!/usr/bin/env python

# CounterStrike attack script!
# (better then @TheRealCounterStrike)

from twisted.python import log
from twisted.protocols.basic import LineReceiver
from twisted.internet import threads, protocol, defer
from twisted.internet.protocol import ReconnectingClientFactory, ProcessProtocol
from sys import stdout, argv
from os import environ
import json, nmap

DEBUG=True
PLAIN = '\033[0m'
RED = '\033[0;31m'
LRED = '\033[1;31m'
GREEN = '\033[0;32m'
LGREEN = '\033[1;32m'
YELLOW = '\033[0;33m'
LYELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
LBLUE = '\033[1;34m'
PURPLE = '\033[0;35m'
LPURPLE = '\033[1;35m'
CYAN = '\033[0;36m'
LCYAN = '\033[1;36m'


def msg(color, identifier, message):
    if not isinstance(message, basestring):
        message = repr(message)
    log.msg(color + identifier +  ' - ' + message + '\033[0m')

class NmapTarget(object):
    nm = nmap.PortScanner()
    nmap_output = None

    def fire(self, remote_ip):
        self.nmap_output = self.nm.scan(remote_ip, arguments='-sV -Pn')
        print json.dumps(self.nmap_output['scan'][remote_ip], indent=4, sort_keys=True)

class NmapReceiver(ProcessProtocol):
    json_output = ''

    def __init__(self, remote_ip, deferred=None):
        self.remote_ip = remote_ip
        self.deferred = deferred

    def done(self, reason):
        msg(LGREEN, '[PROTOCOL][ATTACK]', 'Scan <%s> finished. Reason: <%s>' %
            (self.remote_ip, reason))

    def childDataReceived(self, childFD, data):
        if childFD == 1: self.json_output += data

    def errReceived(self, data):
        msg(LRED, '[NMAP][RECEIVER]', 'Error received (%d bytes): <%s>' % (len(data), str(data)))

    def processEnded(self, reason):
        if reason.value.exitCode == 0:
            self.done('Nmap succeeded')
            if self.deferred is not None:
                self.deferred.callback(self.json_output)
            else:
                print self.json_output
        else:
            self.done(reason)

class JsonReceiver(LineReceiver):
    delimiter = '\n'

    def __init__(self, targets):
        self.targets = targets

    def lineReceived(self, data):
        if DEBUG:
            msg(PLAIN, '[PROTOCOL][DATA]', str(data))
        try:
            proto_json = json.loads(data)
        except ValueError as verr:
            msg(LRED, '[PROTOCOL][JSON]', str(verr))
        else:
            self.dispatch(proto_json)
            pass

    def isValidProtocol(self, proto_json):
        for key in ['event']:
            if key not in proto_json:
                msg(LRED, '[PROTOCOL][DISPATCH]', 'Missing json key/value `event`')
                return False
        return True

    def setProtocolData(self, proto_json):
        self.event     = proto_json['event']
        self.session   = proto_json.get('session', {})
        self.auths     = self.session.get('auths', [{}])
        self.remote_ip = self.session.get('peer_ip', None)
        self.country   = self.session.get('country', '')

    def dispatch(self, proto_json):
        if not self.isValidProtocol(proto_json):
            return
        self.setProtocolData(proto_json)

        if 'connection_made' == self.event:
            msg(PLAIN, '[PROTOCOL][DISPATCH]', 'Incoming connection from <%s> <%s>' %
                (str(self.remote_ip), self.country))
        elif 'login_successful' == self.event:
            msg(LCYAN, '[PROTOCOL][DISPATCH]', 'Starting counter attack on <%s> <%s>' % 
                (str(self.remote_ip), self.country))
            if self.remote_ip is None:
                msg(LRED, '[PROTOCOL][DISPATCH]', 'Missing json key/value(str) `peer_ip`')
                return

            def nmap_succeeded(json_output):
                print str(json_output)

            d = defer.Deferred()
            d.addCallback(nmap_succeeded)
            reactor.spawnProcess(NmapReceiver(self.remote_ip, d), argv[0],
                [argv[0], "nmap", self.remote_ip],
                environ, usePTY=True)

class CounterFactory(ReconnectingClientFactory):
    maxDelay = 5
    targets = {}

    def startedConnecting(self, connector):
        msg(PLAIN, '[FACTORY]', 'Started to connect')

    def buildProtocol(self, addr):
        msg(LGREEN, '[FACTORY]', 'Connected to %s' % (addr))
        return JsonReceiver(self.targets)

    def clientConnectionLost(self, connector, reason):
        msg(LYELLOW, '[FACTORY]', 'Lost connection.  Reason: %s' % (reason))

    def clientConnectionFailed(self, connector, reason):
        msg(LRED, '[FACTORY]', 'Connection failed. Reason: %s' % (reason))
        self.retry(connector)

if __name__ == '__main__':
    from sys import exit
    from twisted.internet import reactor

    # NMAP target
    if len(argv) == 3:
        if argv[1] == 'nmap':
            NmapTarget().fire(argv[2])
            exit(0)
    if len(argv) == 0:
        exit(1)
    if len(argv) != 2:
        print('usage: %s [path-to-honssh-socket]' % (argv[0]))
        exit(2)

    log.startLogging(stdout)
    msg(LPURPLE, '[MAIN]', 'HonSSH-CounterStrike')
    msg(LPURPLE, '[MAIN]', '(C) 2018 by Toni Uhlig')
    reactor.connectUNIX(argv[1], CounterFactory())
    reactor.run()

