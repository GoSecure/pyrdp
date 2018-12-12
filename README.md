# PyRDP
PyRDP is a Python 3 Remote Desktop Protocol (RDP) Man-in-the-Middle (MITM) and library.

It has two main tools:
- RDP Man-in-the-Middle
    - Logs credentials used to connect
    - Steals data copied to the clipboard
    - Saves a copy of the files transferred over the network
    - Saves replays of connections so you can look at them later
- RDP Player:
    - See live RDP connections coming from the MITM
    - View replays of RDP connections

We are using this tool as part of an RDP honeypot which records sessions and saves a copy of the malware dropped on our
target machine.

## Supported systems
PyRDP should work on Python 3.6 and up.

This tool has been tested to work on Python 3.6 on Linux (Ubuntu 18.04). It has not been tested on OSX and Windows.

### Installing on Windows
If you want to install PyRDP on Windows, note that `setup.py` will try to compile `ext/rle.c`, so you will need to have
a C compiler installed. You will also need to generate a private key and certificate to run the MITM.

## Installing
First, make sure to update setuptools so the setup script won't break:

```
sudo pip3 install --upgrade setuptools
```

If you want to run the player, you will also need PyQt4:

```
sudo apt install python3-pyqt4
```

You can now install PyRDP by running the setup script:

```
sudo python3 setup.py install
```

This should install all the dependencies required to run PyRDP.

## Using the PyRDP MITM
Use `pyrdp-mitm.py <ServerIP>` or `pyrdp-mitm.py <ServerIP>:<ServerPort>` to run the MITM.

Assuming you have an RDP server running on `192.168.1.10` and listening on port 3389, you would run:

```
pyrdp-mitm.py 192.168.1.10
```

When running the MITM for the first time on Linux, a private key and certificate should be generated for you in `~/.config/pyrdp`.
These are used when TLS security is used on a connection. You can use them to decrypt PyRDP traffic in Wireshark, for
example.

### Specifying the private key and certificate
If key generation didn't work or you want to use a custom key and certificate, you can specify them using the
`-c` and `-k` arguments:

```
pyrdp-mitm.py 192.168.1.10 -k private_key.pem -c certificate.pem
``` 

### Connecting to the PyRDP player
If you want to see live RDP connections through the PyRDP player, you will need to specify the ip and port on which the
player is listening using the `-i` and `-d` arguments. Note: the port argument is optional, the default port is 3000.

```
pyrdp-mitm.py 192.168.1.10 -i 127.0.0.1 -d 3000
```

#### Connecting to a PyRDP player when the MITM is running on a server
If you are running the MITM on a server and still want to see live RDP connections, you should use
[SSH remote port forwarding](https://www.booleanworld.com/guide-ssh-port-forwarding-tunnelling/)
to forward a port on your server to the player's port on your machine. Once this is done, you pass `127.0.0.1` and the forwarded
port as arguments to the MITM. For example, if port 4000 on the server is forwarded to port 3000 on your machine, this would
be the command to use:

```
pyrdp-mitm.py 192.168.1.10 -i 127.0.0.1 -d 4000
```

### Other MITM arguments
Run `pyrdp-mitm.py --help` for a full list of arguments.

## Using the PyRDP player
Use `pyrdp-player.py` to run the player.

### Playing a replay file
You can use the menu to open a new replay file: File > Open.

You can also open replay files when launching the player:

```
pyrdp-player.py <FILE1> <FILE2> ...
```

### Listening for live connections
The player always listens for live connections. By default, the listening port is 3000, but it can be changed:

```
pyrdp-player.py -p <PORT>
``` 

### Changing the listening address
By default, the player only listens to connections coming from the local machine. We do not recommend opening up the player
to other machines. If you still want to change the listening address, you can do it with `-b`:

```
pyrdp-player.py -b <ADDRESS>
```

### Other player arguments
Run `pyrdp-player.py --help` for a full list of arguments.

## RDP Network Layers

PyRDP uses these layers to manage the many protocols that RDP uses:

![layers](https://user-images.githubusercontent.com/14599855/49668060-03421400-fa2b-11e8-8843-cabfb46d34b4.png)

For a more detailed explanation, head to `docs/layers.md`.

## Contribution guidelines

1. Open an issue before starting your work;
2. Use Python3 type hinting whenever possible to remove ambiguity;

    2.1. If you come across restructuredText type hinting (such us `:type param1: str`), please change it to Python 3 type hinting `def function1(param1: str)`
3. Document your methods and classes with docstrings using the reStructuredText syntax;
4. Respect PEP8 (except for the naming convention, use camelCase).
5. Whenever possible, use format strings (`f"My variable: {myVariable}"`) instead of %-style formating or `str.format()`

    5.1. For log statements, use %-style formatting like that: `myLogger.info("My log message and here's a variable: %(myNamedVariable)s", {"myNamedVariable": myNamedVariable})`.
    This separates variables from the message, which can be helpful for analysis purposes. 

## Acknowledgements
PyRDP uses code from the following open-source software:

- [RC4-Python](https://github.com/bozhu/RC4-Python) for the RC4 implementation.
- [rdesktop](https://github.com/rdesktop/rdesktop) for bitmap decompression.
- [rdpy](https://github.com/citronneur/rdpy) for RC4 keys, the bitmap decompression bindings and the base GUI code for the
PyRDP player.