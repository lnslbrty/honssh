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

from honssh import log

from honssh.config import Config
from honssh.utils import validation

from threading import Lock, Event

import subprocess
import socket
import time


global LOGPREF, QEMU_EXEC, QEMU_IMAG, QEMU_ARGS, ACTIVE_ATTACKER, ATTACKER_EVENT, QEMU_PROCESS
LOGPREF = '[PLUGIN][QEMU]'
QEMU_RTIM = 20
QEMU_EXEC = 'qemu-system-i386'
QEMU_IMAG = 'buildroot/bzImage'
QEMU_VNCP = 5901
QEMU_ARGS = '-enable-kvm -cpu host -m 256 -smp 1 -net nic,model=virtio -net user,hostfwd=tcp:{3:s}:{0:d}-:22 -kernel {1:s} -vnc 127.0.0.1:{2:d}'


QEMU_PROCESS = None

class AtomicCounter:
    def __init__(self, initial=0):
        self.value = initial
        self._lock = Lock()

    def increment(self, num=1):
        with self._lock:
            self.value += num
            return self.value

ACTIVE_ATTACKER = AtomicCounter()
ATTACKER_EVENT = Event()

class Plugin():

    def __init__(self):
        global ATTACKER_EVENT
        ATTACKER_EVENT.clear()
        self.cfg = Config.getInstance()

    def channel_opened(self, sensor):
        global ACTIVE_ATTACKER, ATTACKER_EVENT
        ACTIVE_ATTACKER.increment(1)
        ATTACKER_EVENT.set()

    def channel_closed(self, sensor):
        global ACTIVE_ATTACKER, ATTACKER_EVENT

        ATTACKER_EVENT.clear()
        if ACTIVE_ATTACKER.value == 1:
            log.msg(log.RED, LOGPREF, 'No attacker remaining, restarting QEMU in %ds' % (self.cfg.getint(['qemu', 'restart_time'], default=QEMU_RTIM)))
            if ATTACKER_EVENT.wait( self.cfg.getint(['qemu', 'restart_time'], default=QEMU_RTIM) ) is not True:
                log.msg(log.RED, LOGPREF, 'RESTARTING QEMU instance')
                if self.qemu_stop() is False:
                    log.msg(log.RED, LOGPREF, 'FATAL: QEMU instance failed to stop')
                if self.qemu_start() is False:
                    log.msg(log.RED, LOGPREF, 'FATAL: QEMU instance failed to start')
            else:
                log.msg(log.RED, LOGPREF, 'ABORT RESTARTING QEMU instance, active attacker: %d' % (ACTIVE_ATTACKER.value))

        log.msg(log.RED, LOGPREF, 'Remaining attacker: %d' % (ACTIVE_ATTACKER.increment(-1)))

    def validate_config(self):
        if self.cfg.getboolean(['honeypot-static', 'enabled'], default=False) is False:
            log.msg(log.RED, LOGPREF, 'QEMU requires honeypot-static')
            return False

        props = [['qemu', 'enabled', validation.check_valid_boolean],
                 ['qemu', 'restart', validation.check_valid_boolean]]
        for prop in props:
            if not self.cfg.check_exist(prop, prop[2]):
                return False

        log.msg(log.GREEN, LOGPREF, 'Starting QEMU instance')
        if self.qemu_start() is True:
            log.msg(log.GREEN, LOGPREF, 'Waiting for QEMU instance')
            self.qemu_wait_guest_ssh()
        else:
            log.msg(log.RED, LOGPREF, 'QEMU instance failed to start')
            return False

        return True

    def qemu_start(self):
        global QEMU_PROCESS
        if QEMU_PROCESS is None:
            exe = self.cfg.get(['qemu', 'exec'], default=QEMU_EXEC)
            args = QEMU_ARGS.format(self.cfg.getint(['honeypot-static', 'honey_port']),
                       self.cfg.get(['qemu', 'image'], default=QEMU_IMAG),
                       self.cfg.getint(['qemu', 'vnc'], default=QEMU_VNCP),
                       self.cfg.get(['honeypot-static', 'honey_ip']))
            log.msg(log.PLAIN, LOGPREF, 'running cmd: ' + exe + ' ' +args)
            QEMU_PROCESS = subprocess.Popen([exe] + args.split(' '), executable=exe)
        if QEMU_PROCESS is not None:
            return True
        return False

    def qemu_stop(self):
        global QEMU_PROCESS
        if QEMU_PROCESS is not None:
            QEMU_PROCESS.kill()
            QEMU_PROCESS.wait()
            QEMU_PROCESS = None
            return True
        return False

    def qemu_wait_guest_ssh(self):
        testsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        run = True
        while run:
            try:
                testsock.connect( (self.cfg.get(['honeypot-static', 'honey_ip']), self.cfg.getint(['honeypot-static', 'honey_port'])) )
                testsock.close()
                run = False
            except socket.error, exc:
                log.msg(log.PLAIN, LOGPREF, 'QEMU not ready, SSH connection failed: %s' % (str(exc)))
                time.sleep(0.25)
                continue
