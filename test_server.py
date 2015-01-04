#!/usr/bin/env python

# Copyright (C) 2015 Jouni Roivas <jroivas@iki.fi>

import sshserver

class MyHandler(sshserver.SSHThread):
    def __init__(self, conn, key_handler):
        sshserver.SSHThread.__init__(self, conn, key_handler)

    def handler(self, transport, server, channel):
        channel.send('Hi %s, fingerprint %s\r\n' %
            (server.username,
             self.key_handler.key_str(server.key.get_fingerprint())))
        channel.send('Write "exit" to quit.\r\n\r\n')

        fd = channel.makefile('rU')
        channel.send('entry: ')
        data = ''

        while self.running:
            tmp = fd.read(1)
            if ord(tmp) == 127:  # Special backspace
                if data:
                    data = data[:-1]
                    channel.send('\b \b')
            elif tmp == '\n' or tmp == '\r':
                channel.send('\r\n')
                if data.strip() == 'exit':
                    self.running = False
                channel.send(data.strip() + '\r\n')
                channel.send('entry: ')
                data = ''
            else:
                data += tmp
                channel.send(tmp)


if __name__ == '__main__':
    key_handler = sshserver.SSHKeyHandler(auth_file='auth_keys', host_key='~/.ssh/id_rsa')
    server = sshserver.ThreadedSSHServer(MyHandler, key_handler, verbose=True)
    server.start()
    server.join()
