# Copyright (c) 2018 Toni Uhlig <matzeton@googlemail.com>
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

import json

from twisted.internet import reactor, protocol


class HonsshIpc(protocol.Protocol):

    def connectionMade(self):
        self.factory.clients.append(self)

    def dataReceived(self, data):
        self.transport.write(data)

    def connectionLost(self, reason):
        self.factory.clients.remove(self)

class HonsshIpcFactory(protocol.Factory):
    protocol = HonsshIpc

    def __init__(self):
        self.clients = []

    def ipcSendAll(self, event, session):
        session['event'] = str(event)
        for client in self.clients:
            client.transport.write(json.dumps(session) + '\n')

class HonsshIpcDummy(object):

    def ipcSendAll(self, event, session):
        pass

def make_ipc_server(sockpath):
    if sockpath is not None and len(sockpath) > 0:
        ifactory = HonsshIpcFactory()
        reactor.listenUNIX(sockpath, ifactory)
    else:
        ifactory = HonsshIpcDummy()
    return ifactory
