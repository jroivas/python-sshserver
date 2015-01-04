# Copyright (C) 2015 Jouni Roivas <jroivas@iki.fi>

from paramiko.py3compat import decodebytes
import binascii
import os
import paramiko
import socket
import threading

class SSHKeyHandler(object):
    """ Handler for all SSH keys
    """
    def __init__(self, auth_file, host_key):
        """
        @param auth_file Authenticated keys, corresponding to ~/.ssh/authorized_keys but for multiple users
        @param host_key Private key for host
        """
        self.keys = []
        self.host_key = os.path.expanduser(host_key)
        self.ssh_keys = {}
        with open(auth_file, 'r') as fd:
            self.keys = fd.readlines()
        self.parse_ssh_keys()
        self.parse_host_key()

    def key_str(self, key):
        """ Print key in hex format, pair in 8 bit chunks,
        separated with colon.

        @param key Paramiko key to be converted
        @returns Key as hex string
        """
        res = ''
        tmp = binascii.hexlify(key)
        for i, x in enumerate(tmp):
            if i > 0 and i % 2 == 0:
                res += ':'
            res += x
        return res

    def parse_host_key(self):
        """ Reads defined host key and parses it
        """
        self.host_key = paramiko.RSAKey(filename=self.host_key)

    def parse_ssh_keys(self):
        """ Parse "authorized_keys" style ssh key file
        Currently accepted scheme: ssh-rsa KEY user@host
        Parses user name from last entry, so it needs to be correct
        """
        for key in self.keys:
            entries = key.split(' ')
            if len(entries) != 3:
                continue
            if entries[0] != 'ssh-rsa':
                continue

            user = entries[2].split('@')
            self.add_key(entries[1], user[0])

    def add_key(self, data, user):
        """ Decode key, and make it paramiko RSA key
        Map key for given user.

        @param data Key as string
        @param user User to map the key for
        @returns True on success, False otherwise
        """
        try:
            key = paramiko.RSAKey(data=decodebytes(data))
            if user not in self.ssh_keys:
                self.ssh_keys[user] = []
            self.ssh_keys[user].append(key)

            return True
        except:
            return False

    def user_keys(self, user):
        """ Get keys for giver user

        @param user User whose keys wanted
        @returns List of user keys, or empty list
        """
        if user not in self.ssh_keys:
            return []
        return self.ssh_keys[user]

class SSHServer(paramiko.ServerInterface):
    """ Implements paramiko server
    """
    def __init__(self, key_handler):
        """
        @param key_handler Instance of SSHKeyHandler
        """
        self.event = threading.Event()
        self.ssh_keys = key_handler
        self.username = ''
        self.key = ''

    def check_channel_request(self, kind, chanid):
        """ Check if channel request is ok.
        For now support only session.
        """
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        """ Check for user password. Disabled by default.

        @param username Username to check
        @param password Password to check
        @return paramiko.AUTH_FAILED
        """
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username, key):
        """ Check for public key authentication.
        Utilizes SSHKeyHandler for managing keys.

        @param username Username to check
        @param key User provided public key
        @return paramiko.AUTH_SUCCESSFUL if key found for user, paramiko.AUTH_FAILED otherwise
        """
        keys = self.ssh_keys.user_keys(username)
        if not keys:
            return paramiko.AUTH_FAILED

        if key in keys:
            self.username = username
            self.key = key
            return paramiko.AUTH_SUCCESSFUL

        return paramiko.AUTH_FAILED

    def enable_auth_gssapi(self):
        """ GSSAPI disabled by default
        """
        return False

    def get_allowed_auths(self, username):
        """ Get allowed authentication methods.
        By default supports only publickey.
        Methods are comma separated list.

        Possible values: gssapi-keyex,gssapi-with-mic,password,publickey

        @returns String containing authentication methods
        """
        return 'publickey'

    def check_channel_shell_request(self, channel):
        """ Check if we provide shell

        @returns True if shell is provided, False otherwise
        """
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
        pixelwidth, pixelheight, modes):
        """ Check if we provide pseudo-terminal on given dimensions

        @returns True if pty is provided, False otherwise
        """
        return True

class ThreadedSSHServer(threading.Thread):
    """ Provides threaded SSH server
    """
    def __init__(self, launcher, key_handler, port=2200, instances=100, verbose=False):
        """
        @param launcher Launcher for per-connection handlers
        @param key_handler Instance of SSHKeyHandler
        @param port Port to bind
        @param instances Maximum number of sockets to serve
        """
        threading.Thread.__init__(self)
        self.key_handler = key_handler
        self.launcher = launcher
        self.port = port
        self.instances = instances
        self.workers = []
        self.verbose = verbose

    def __del__(self):
        self.clean_workers(force=True)

    def connect(self):
        """ Handles connection binding and creation of socket

        @returns Socket
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(('', self.port))

        return sock

    def accept(self, sock):
        """ Accept connections on socket

        @param sock Socket
        @return Tuple of cliend and address, or None
        """
        try:
            return sock.accept()
        except Exception as e:
            return None

    def clean_workers(self, timeout=5, force=False):
        """ Cleanup old worker threads

        @param timeout Timeout for this function
        @param force Force termination of all threads
        """
        cnt = 0
        while force or cnt < timeout:
            edited = False
            cnt += 1
            for worker in self.workers:
                del_it = False
                if worker.running and force:
                    worker.running = False
                    del_it = True
                elif not worker.running:
                    del_it = True

                if del_it:
                    worker.join()
                    self.workers.remove(worker)
                    del worker
                    edited = True
                    break

            if not edited:
                return

    def run(self):
        """ Run the SSH server main thread
        """
        sock = self.connect()
        sock.listen(self.instances)
        if self.verbose:
            print ("Serving on port %s" % (self.port))

        while True:
            # Listen for new connections
            client = self.accept(sock)

            self.clean_workers()
            if client is None:
                continue

            # Start new worker thread
            worker = self.launcher(client[0], self.key_handler)
            worker.start()

            self.workers.append(worker)

class SSHThread(threading.Thread):
    """ Base for expandable custom handler threads
    """
    def __init__(self, conn, key_handler, timeout=30):
        """
        @param conn Connection socket
        @param key_handler Instance of SSHKeyHandler
        """
        threading.Thread.__init__(self)
        self.conn = conn
        self.key_handler = key_handler
        self.timeout = timeout
        self.running = False

    def transport(self):
        """ Initialize paramiko transport

        @returns Transport object or None
        """
        try:
            transport = paramiko.Transport(self.conn)
            try:
                transport.load_server_moduli()
            except:
                return None
            transport.add_server_key(self.key_handler.host_key)
        except:
            return None

        return transport

    def serve(self, transport):
        """ Serve on transport layer

        @param transport Transport object
        @return Server instance or None
        """
        if transport is None:
            self.running = False
            return

        server = SSHServer(key_handler=self.key_handler)
        try:
            transport.start_server(server=server)
        except paramiko.SSHException:
            self.running = False
            return None

        return server

    def channel(self, transport):
        """ Get channel from transport layer

        @param transport Transport object
        @returns Channel object
        """
        return transport.accept(self.timeout)

    def handler(self, transport, server, channel):
        """ Handler function to customize behaviour
        Connection is closed when this method ends

        @param transport Transport instance
        @param server Server instance
        @param channel Channel instance
        """
        pass

    def run(self):
        """ Run the thread
        """
        self.running = True

        transporter = self.transport()
        server = self.serve(transporter)
        channel = self.channel(transporter)
        if channel is None:
            tranporter.close()
            self.running = False

        # Wait for event
        server.event.wait(10)
        if not server.event.is_set():
            return

        self.handler(transporter, server, channel)
        channel.close()
