# python-sshserver

Base for implementing various SSH servers and SSH based services with Python.

Utilizes paramiko underneath: http://www.paramiko.org/


## What it is for?

Main motivation was a bit easier way of building on top of SSH.
Idea came from this blog post:
[Why aren’t we using SSH for everything?](https://medium.com/@shazow/ssh-how-does-it-even-9e43586e4ffc)

Target is to increase SSH usage on services, and to provide easy way to implement them in Python.

## Running

Make sure you have paramiko installed either on system or virtualenv.
Example server should work after that without any problems.

Take your public key(s) and put it(them) into auth_keys, this is similar to
traditional SSH ~/.ssh/authorized_keys but this is for multiple users.
Format needs to be:

    ssh-rsa KEY user@host

Remark: user names are parsed from that info.

When you have this set up, start the test server:

    python test_server.py

It will serve by default in port 2200. And you should be able to access it
with proper SSH key:

    ssh -p2200 user@host

Example:

    $ ssh -p2200 user@localhost
    Hi user, fingerprint f2:a9:6f:d3:d5:7f:86:9d:5f:1c:88:33:d6:ec:8d:06
    Write "exit" to quit.

    entry: Hello!
    Hello!
    entry: exit
    exit
    entry: Connection to localhost closed.

Enjoy!
