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

import os, subprocess


LOGPREF = '[PLUGIN][IPTABLES]'


class Plugin():
    def __init__(self):
        self.cfg = Config.getInstance()

    def iptables_redirect(self, hostport, toport, useSudo=True, doCheck=True):
        iptables_cmdstr = 'iptables -t nat %s PREROUTING -p tcp --dport %d -j REDIRECT --to-port %d' % ('-C' if doCheck else '-A', hostport, toport)
        iptables_cmd = iptables_cmdstr.split(' ')
        if useSudo:
            iptables_cmd.insert(0, 'sudo')
        log.msg(log.PLAIN, LOGPREF, 'running cmd: ' + ' '.join(iptables_cmd))
        return subprocess.call(iptables_cmd)

    def iptables_exclude_redirect(self, subnet, useSudo=True, doCheck=True):
        iptables_cmdstr = 'iptables -t nat %s PREROUTING%s ! -s %s -p tcp --dport 22 -j REDIRECT --to-port 22' % \
            ('-C' if doCheck else '-I', '' if doCheck else ' 1', subnet)
        iptables_cmd = iptables_cmdstr.split(' ')
        if useSudo:
            iptables_cmd.insert(0, 'sudo')
        log.msg(log.PLAIN, LOGPREF, 'running cmd: ' + ' '.join(iptables_cmd))
        return subprocess.call(iptables_cmd)

    def validate_config(self):
        props = [['iptables', 'enabled'], ['iptables', 'sudo']]
        for prop in props:
            if not self.cfg._getconv(prop):
                return False

        subnets = self.cfg.get(['iptables', 'exclude'], raw=True, vars=None, default='')
        if len(subnets) > 0:
            for subnet in subnets.split(','):
                useSudo = self.cfg.getboolean(['iptables','sudo'], default=True)
                retval = self.iptables_exclude_redirect(subnet, useSudo=useSudo)
                if retval == 1:
                    if self.iptables_exclude_redirect(subnet, useSudo=useSudo, doCheck=False) == 0:
                        log.msg(log.GREEN, LOGPREF, 'Rule append ok: exclude ' + str(subnet))
                    else:
                        log.msg(log.RED, LOGPREF, 'Rule append FAILED: exclude ' + str(subnet))
                elif retval == 0:
                    log.msg(log.GREEN, LOGPREF, 'Rule `exclude ' + str(subnet) + '` does already exist')
                else:
                    log.msg(log.RED, LOGPREF, 'Rule check FAILED: `exclude ' + str(subnet) + '`')

        options = self.cfg.options('iptables')
        for opt in options:
            if opt == 'exclude': continue
            if not self.cfg.check_exist(['iptables',opt], validation.check_valid_boolean): continue
            if not self.cfg.getboolean(['iptables', opt], default=False): continue
            lst = opt.split('_')
            if type(lst) == list and len(lst) == 4:
                if lst[0] == 'redirect' and lst[2] == 'to':
                    dwHostPort, dwToPort, useSudo = int(lst[1]), int(lst[3]), self.cfg.getboolean(['iptables','sudo'], default=True)
                    retval = self.iptables_redirect(dwHostPort, dwToPort, useSudo=useSudo)
                    if retval == 1:
                        if self.iptables_redirect(dwHostPort, dwToPort, useSudo=useSudo, doCheck=False) == 0:
                            log.msg(log.GREEN, LOGPREF, 'Rule append ok: ' + str(opt))
                        else:
                            log.msg(log.RED, LOGPREF, 'Rule append FAILED: ' + str(opt))
                    elif retval == 0:
                        log.msg(log.GREEN, LOGPREF, 'Rule ' + str(opt) + ' does already exist')
                    else:
                        log.msg(log.RED, LOGPREF, 'Rule check FAILED: ' + str(opt))
        return True
