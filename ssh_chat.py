#!/usr/bin/env python

# Copyright (C) 2015 Jouni Roivas <jroivas@iki.fi>

import sshserver

class ChatServer(sshserver.SSHServer):
    def __init__(self, key_handler):
        super(ChatServer, self).__init__(key_handler)
        self.key_handler.users = {}

    def check_auth_publickey(self, username, key):
        # Overriding default method to automatically
        # allow any client
        if not username:
            return self.auth_fail()

        self.username = username
        if username in self.key_handler.users:
            if self.key_handler.users[username] == key:
                return self.auth_success()
            return self.auth_fail()

        # Now only this username can login
        self.key_handler.users[username] = key

        return self.auth_success()

class ChatHandler(sshserver.SSHThread):
    def __init__(self, conn, key_handler, master):
        super(ChatHandler, self).__init__( conn, key_handler, master)
        self.motd = 'Welcome to simple Python SSH chat'
        self.server_class = ChatServer

    def name(self):
        return self._server.username

    def sendAll(self, msg):
        if not msg:
            return
        for worker in self.master.workers:
            if worker._channel is not None:
                try:
                    # Hack to prevent messing things...
                    data = u'%s: %s\r\n' % (self.name(), msg)
                    worker._channel.send(data.encode('utf-8'))
                except:
                    pass

    def handler(self):
        self._channel.send('%s\r\n' % self.motd)

        fd = self._channel.makefile('rU')
        self._channel.send('[%s] ' % (self.name()))
        data = ''

        while self.running:
            tmp = fd.read(1)
            if ord(tmp) == 4:
                self.running = False
            elif ord(tmp) == 127:  # Special backspace
                if data:
                    data = data[:-1]
                    self._channel.send('\b \b')
            elif tmp == '\n' or tmp == '\r':
                self._channel.send('\r\n')
                if data.strip() == 'exit':
                    self.running = False
                try:
                    self.sendAll(data.strip().decode('utf-8'))
                except:
                    self._channel.send('*** GOT INVALID DATA')
                self._channel.send('[%s] ' % (self.name()))
                data = ''
            else:
                data += tmp
                self._channel.send(tmp)

if __name__ == '__main__':
    key_handler = sshserver.SSHKeyHandler(auth_file='auth_keys', host_key='~/.ssh/id_rsa')
    server = sshserver.ThreadedSSHServer(ChatHandler, key_handler, verbose=True)
    server.start()
    server.join()
