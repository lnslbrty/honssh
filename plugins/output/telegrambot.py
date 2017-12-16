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

import telegram
from telegram.error import NetworkError, Unauthorized


class Plugin():
    def tgSend(self, text):
        try:
            self.bot.sendMessage(chat_id=self.chat_id, text=text, parse_mode=telegram.ParseMode.HTML)
        except Exception as err:
            log.msg(log.RED, '[PLUGIN][TELEGRAM]', str(err))

    def __init__(self):
        self.cfg = Config.getInstance()
        self.auth_token = self.cfg.get   (['telegrambot', 'auth_token'])
        self.chat_id    = self.cfg.getint(['telegrambot', 'chat_id'])
        try:
            self.bot = telegram.Bot(self.auth_token)
            log.msg(log.GREEN, '[PLUGIN][TELEGRAM]', 'User/ID: %s/%s' % \
                (str(self.bot.get_me().username), str(self.bot.get_me().id)))
        except Exception as err:
            log.msg(log.RED, '[PLUGIN][TELEGRAM]', str(err))

    def start_server(self):
        self.tgSend('<b>Server started.</b>')

    def set_server(self, server):
        pass

    def connection_made(self, sensor):
        session = sensor['session']
        self.tgSend('Connection from <a href="http://%s">%s:%s</a>\n%s' % \
            (session['peer_ip'], session['peer_ip'], session['peer_port'], \
            '<code>Country: '+session['country']+'</code>\n' if len(session['country']) > 0 else ''))

    def connection_lost(self, sensor):
        session = sensor['session']
        self.tgSend('<b>LOST</b> Connection to %s:%s\n' % (session['peer_ip'], session['peer_port']))

    def set_client(self, sensor):
        pass

    def login_successful(self, sensor):
        session = sensor['session']
        auth = session['auth']
        self.tgSend('Login <b>SUCCESS</b> from %s:%s\n<code>user: %s\npass: %s\nversion: %s</code>\n' % \
            (session['peer_ip'], session['peer_port'], \
            auth['username'], auth['password'], session['version']))

    def login_failed(self, sensor):
        pass

    def channel_opened(self, sensor):
        pass

    def channel_closed(self, sensor):
        pass

    def command_entered(self, sensor):
        pass

    def download_started(self, sensor):
        pass

    def download_finished(self, sensor):
        pass

    def packet_logged(self, sensor):
        pass

    def validate_config(self):
        props = [['telegrambot', 'enabled'],
                 ['telegrambot', 'auth_token'],
                 ['telegrambot', 'chat_id']]
        for prop in props:
            if not self.cfg.check_exist(prop):
                return False
        return True
