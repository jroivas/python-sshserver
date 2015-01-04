#!/usr/bin/env python

# Copyright (C) 2015 Jouni Roivas <jroivas@iki.fi>

import sshserver

class MyHandler(sshserver.SSHThread):
    def __init__(self, conn, key_handler, master):
        sshserver.SSHThread.__init__(self, conn, key_handler, master)

    def handler(self):
        self._channel.send('Hi %s, fingerprint %s\r\n' %
            (self._server.username,
             self.key_handler.key_str(self._server.key.get_fingerprint())))
        self._channel.send('Write "exit" to quit.\r\n\r\n')

        fd = self._channel.makefile('rU')
        self._channel.send('entry: ')
        data = ''

        while self.running:
            tmp = fd.read(1)
            if ord(tmp) == 127:  # Special backspace
                if data:
                    data = data[:-1]
                    self._channel.send('\b \b')
            elif tmp == '\n' or tmp == '\r':
                self._channel.send('\r\n')
                if data.strip() == 'exit':
                    self.running = False
                self._channel.send(data.strip() + '\r\n')
                self._channel.send('entry: ')
                data = ''
            else:
                data += tmp
                self._channel.send(tmp)


if __name__ == '__main__':
    key_handler = sshserver.SSHKeyHandler(auth_file='auth_keys', host_key='~/.ssh/id_rsa')
    server = sshserver.ThreadedSSHServer(MyHandler, key_handler, verbose=True)
    server.start()
    server.join()
