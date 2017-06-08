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


LOGPREF = '[PLUGIN][SSH-KEYGEN]'


class Plugin():
    def __init__(self):
        self.cfg = Config.getInstance()

    def ssh_keygen(self):
        rsa_prv = self.cfg.get(['honeypot', 'private_key'])
        rsa_pub = self.cfg.get(['honeypot', 'public_key'])
        dsa_prv = self.cfg.get(['honeypot', 'private_key_dsa'])
        dsa_pub = self.cfg.get(['honeypot', 'public_key_dsa'])
        for file in [rsa_prv, rsa_pub, dsa_prv, dsa_pub]:
            if os.path.exists(file): os.remove(file)
        ret = subprocess.call([ "ssh-keygen", "-t", "rsa", "-N", "", "-f", rsa_prv])
        if ret != 0:
            log.msg(log.RED, LOGPREF, '[ERR][FATAL] could not generate %s' % (rsa_prv))
            return False
        ret = subprocess.call([ "ssh-keygen", "-t", "dsa", "-N", "", "-f", dsa_prv])
        if ret != 0:
            log.msg(log.RED, LOGPREF, '[ERR][FATAL] could not generate %s' % (dsa_prv))
            return False
        os.rename(str(rsa_prv)+'.pub', str(rsa_pub))
        os.rename(str(dsa_prv)+'.pub', str(dsa_pub))
        return True

    def validate_config(self):
        props = [['ssh-keygen', 'enabled']]
        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean):
                return False

        props = [['honeypot', 'private_key'], ['honeypot', 'public_key'], ['honeypot', 'private_key_dsa'], ['honeypot', 'public_key_dsa']]
        for prop in props:
            if  not self.cfg.check_exist(prop, None):
                return False

        if self.ssh_keygen() is False:
            log.msg(log.RED, LOGPREF, 'Generating rsa/dsa private/public keys failed!')
            return False
        log.msg(log.GREEN, LOGPREF, 'Generated rsa/dsa private/public keys')
        return True
