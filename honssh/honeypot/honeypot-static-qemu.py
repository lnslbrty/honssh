#!/usr/bin/env python

# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from os import environ
from copy import deepcopy
from random import randint
from twisted.internet import reactor, defer
from twisted.internet.protocol import ProcessProtocol
from honssh.config import Config
from honssh.utils import validation
from honssh.log import msg
from honssh import spoof, log


class QemuProcessProtocol(ProcessProtocol):
    def __init__(self, qid):
        self.qid = qid
    def done(self, reason):
        msg(log.LGREEN, '[QEMU][PROCESS]', 'Qemu instance <%d> finished. Result: <%s>' %
            (self.qid, reason))
    def childDataReceived(self, childFD, data):
        if data[-1:] == '\n':
            data = data[:-1]
        if childFD == 1:
            msg(log.PLAIN, '[QEMU][PROCESS]', 'Qemu instance <%d> stdout: <%s>' %
                (self.qid, str(data)))
        elif childFD == 2:
            msg(log.LRED, '[QEMU][PROCESS]', 'Qemu instance <%d> stderr: <%s>' %
                (self.qid, str(data)))
    def errReceived(self, data):
        msg(log.LRED, '[QEMU][PROCESS]', 'Qemu instance <%d> ERROR: <%s>' %
            (self.qid, str(data)))
    def processEnded(self, reason):
        ecode = reason.value.exitCode
        if ecode is not None:
            msg(log.LPURPLE if ecode == 0 else log.LRED,
                '[QEMU][PROCESS]', 'Qemu instance <%d> exited with <%d>' %
                (self.qid, ecode))
        else:
            msg(log.LPURPLE, '[QEMU][PROCESS]', 'Qemu instance <%d> exited' % (self.qid))

class Qemu(object):
    started = False
    proc = None
    EXEC = 'qemu-system-i386'
    IMAG = 'buildroot/bzImage'
    VNCS = 8
    BIND = '127.0.0.1'
    PORT = 22223
    MEMO = 64
    CORS = 1
    ARGS = ['-enable-kvm','-cpu','host','-m','{MEMO:d}','-smp','{CORS:d}','-net',
            'nic,model=virtio',
            '-net','user,hostfwd=tcp:{BIND:s}:{PORT:d}-:22','-kernel','{IMAG:s}',
            '-vnc','127.0.0.1:{VNCS:d}']
    allowed_attrs = ['EXEC','IMAG','VNCS',
                     'BIND','PORT','MEMO',
                     'CORS','ARGS']

    def __init__(self, qid):
        self.qid = qid
        self.PORT += qid
        self.VNCS += qid

    def set_qemu_details(self, **kwargs):
        for key, value in kwargs.items():
            if key in self.allowed_attrs:
                setattr(self, key, value)
            else:
                raise AttributeError('Key <%s> from kwargs not allowed!' %
                    (key))

    def get_qemu_details(self):
        outdict = {}
        for key in self.allowed_attrs:
            outdict[key] = getattr(self, key)
        return outdict

    def start(self):
        arglist = self.build_qemu_args(self.EXEC)
        msg(log.LPURPLE, '[QEMU]', 'Starting instance <%d>: <%s>' %
            (self.qid, self.EXEC))
        msg(log.LPURPLE, '[QEMU]', 'Args for instance <%d>: <%s>' %
            (self.qid, ' '.join(arglist)))
        self.proc = reactor.spawnProcess(
            QemuProcessProtocol(self.qid), self.EXEC, [self.EXEC] + arglist,
            environ, usePTY=False,
            childFDs={1:'r',2:'r'}
        )
        self.started = True

    def stop(self):
        self.proc.signalProcess('KILL')
        self.started = False

    def build_qemu_args(self, arg0):
        outargs = []
        kwargs = self.get_qemu_details()
        for arg in self.ARGS:
            outargs.append(arg.format(**kwargs))
        return outargs

class Peer(object):
    qemu = None
    count = 0

    def __init__(self, qemu):
        self.qemu = qemu

class QemuManager(object):
    _instance = None
    _qemus = []
    _peers = {}
    _plock = defer.DeferredLock()

    @classmethod
    def getInstance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return  cls._instance

    def __init__(self):
        self._qemu_max_instances = 4
        for i in range(self._qemu_max_instances):
            self._qemus.append(Qemu(i))
        reactor.addSystemEventTrigger('before', 'shutdown', self.stopAll)

    def start(self, qid):
        return self._qemus[qid].start()

    def startAll(self):
        for qemu in self._qemus:
            qemu.start()

    def _allStoppedCallback(self):
        msg(log.LYELLOW, '[QEMU][Shutdown]', 'Waiting for all instances to terminate ..')
        for qemu in self._qemus:
            if qemu.proc.pid is not None:
                d = defer.Deferred()
                reactor.callLater(1, d.callback, None)
                return d
            else:
                qemu.proc.loseConnection()
        return None

    def stop(self, qid):
        return self._qemus[qid].stop()

    def stopAll(self):
        for qemu in self._qemus:
            qemu.proc.signalProcess('KILL')
        return self._allStoppedCallback()

    def availableInstance(self, peer_ip):
        if peer_ip not in self._peers:
            inst = self._qemus[randint(0, len(self._qemus)-1)]
            while inst.started is False:
                inst = self._qemus[randint(0, len(self._qemus)-1)]
            self._peers[peer_ip] = Peer(inst)
        else:
            inst = self._peers[peer_ip].qemu
        return (inst.BIND, inst.PORT)

    def acquireInstance(self, peer_ip):
        inst = self._peers[peer_ip].qemu
        self._peers[peer_ip].count += 1
        msg(log.LYELLOW, '[QEMU]', 'Acquired instance <%d> for <%s> #<%d>' %
            (inst.qid, peer_ip, self._peers[peer_ip].count))

    def releaseInstance(self, peer_ip, login_succeeded):
        if peer_ip in self._peers:
            inst = self._peers[peer_ip].qemu
            if login_succeeded is True:
                self._peers[peer_ip].count -= 1
            if self._peers[peer_ip].count == 0:
                del self._peers[peer_ip]

class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.qemu = QemuManager.getInstance()
        self.connection_timeout = self.cfg.getint(['honeypot', 'connection_timeout'])
        self.login_succeeded = False

    def get_pre_auth_details(self, conn_details):
        details = self.get_connection_details(conn_details)
        return details

    def get_post_auth_details(self, conn_details):
        success, username, password = spoof.get_connection_details(conn_details)
        if success:
            details = self.get_connection_details(conn_details)
            details['username'] = username
            details['password'] = password
        else:
            details = {'success': False}
        return details

    def login_successful(self):
        self.qemu.acquireInstance(self.peer_ip)
        self.login_succeeded = True

    def connection_lost(self, conn_details):
        self.qemu.releaseInstance(self.peer_ip, self.login_succeeded)

    def start_server(self):
        self.qemu.startAll()

    def get_connection_details(self, conn_details):
        honey_ip, honey_port = self.qemu.availableInstance(conn_details['peer_ip'])
        self.peer_ip = conn_details['peer_ip']
        return {'success': True, 'sensor_name': 'Qemu', 'honey_ip': honey_ip, 'honey_port': honey_port,
                'connection_timeout': self.connection_timeout}

    def validate_config(self):
        section = 'honeypot-static-qemu'
        props = [[section, 'enabled'], [section, 'pre-auth'], [section, 'post-auth']]
        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean):
                return False

        Qemu.EXEC = self.cfg.get([section, 'exec'], Qemu.EXEC)
        Qemu.IMAG = self.cfg.get([section, 'image'], Qemu.IMAG)
        Qemu.VNCS = self.cfg.getint([section, 'vnc-start'], Qemu.VNCS)
        Qemu.PORT = self.cfg.getint([section, 'ssh-start'], Qemu.PORT)
        Qemu.MEMO = self.cfg.getint([section, 'memory'], Qemu.MEMO)
        Qemu.CORS = self.cfg.getint([section, 'cpus'], Qemu.CORS)

        return True
