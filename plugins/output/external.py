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

import subprocess, os

DEVNULL = open(os.devnull, 'rw')
SCRIPT_EVENTS = [
    'on_start_server','on_connection_made','on_connection_lost',
    'on_login_successful','on_login_failed','on_channel_opened',
    'on_channel_closed','on_download_started','on_download_finished',
]

class Plugin():
    def __init__(self):
        self.cfg = Config.getInstance()
        self.scripts = {}
        for ev in SCRIPT_EVENTS:
            self.scripts[ev] = self.cfg.get(['external',ev], default=None)

    def run_script(self, event, sensor=None):
        if self.scripts[event] is not None and len(self.scripts[event]) > 0:
            log.msg(log.GREEN, '[PLUGIN][EXTERNAL]', 'EVENT: %s, running script: %s' % \
                (event, self.scripts[event]))
            # prepare env key/values
            env = os.environ.copy()
            if sensor is not None:
                # session env
                for s in ['country','start_time','session_id','peer_port','peer_ip']:
                    env[s] = str(sensor['session'][s])
                # auth env
                if 'auths' in sensor['session'] and len(sensor['session']['auths']) > 0:
                    for s in ['username','spoofed','password','success']:
                        env[s] = str(sensor['session']['auths'][0][s])
            try:
                # run cmd specified in cfg
                subprocess.Popen(self.scripts[event], env=env, shell=False, close_fds=True, stdin=DEVNULL)
            except OSError:
                pass

    def start_server(self):
        self.run_script('on_start_server')

    def connection_made(self, sensor):
        self.run_script('on_connection_made', sensor)

    def connection_lost(self, sensor):
        self.run_script('on_connection_lost', sensor)

    def login_successful(self, sensor):
        self.run_script('on_login_successful', sensor)

    def login_failed(self, sensor):
        self.run_script('on_login_failed', sensor)

    def channel_opened(self, sensor):
        self.run_script('on_channel_opened', sensor)

    def channel_closed(self, sensor):
        self.run_script('on_channel_closed', sensor)

    def download_started(self, sensor):
        self.run_script('on_download_started', sensor)

    def download_finished(self, sensor):
        self.run_script('on_download_finished', sensor)

    def validate_config(self):
        props = [['external', 'enabled']]
        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean):
                return False
        if self.cfg.get(prop[0]) is False:
            return False

        log.msg(log.GREEN, '[PLUGIN][EXTERNAL]', 'Enabled')
        return True
