# PyRDP
PyRDP is a Python 3 Remote Desktop Protocol (RDP) Man-in-the-Middle (MITM) and library.

It features a few tools:
- RDP Man-in-the-Middle
    - Logs credentials used to connect
    - Steals data copied to the clipboard
    - Saves a copy of the files transferred over the network
    - Saves replays of connections so you can look at them later
- RDP Player:
    - See live RDP connections coming from the MITM
    - View replays of RDP connections
- RDP Certificate Cloner:
    - Create a self-signed X509 certificate with the same fields as an RDP server's certificate

We are using this tool as part of an RDP honeypot which records sessions and saves a copy of the malware dropped on our
target machine.

## Table of Contents
- [Supported Systems](#supported-systems)
- [Installing](#installing)
    * [Installing on Windows](#installing-on-windows)
- [Using the PyRDP MITM](#using-the-pyrdp-mitm)
    * [Specifying the private key and certificate](#specifying-the-private-key-and-certificate)
    * [Connecting to the PyRDP player](#connecting-to-the-pyrdp-player)
        + [Connecting to a PyRDP player when the MITM is running on a server](#connecting-to-a-pyrdp-player-when-the-mitm-is-running-on-a-server)
    * [Other MITM arguments](#other-mitm-arguments)
- [Using the PyRDP Player](#using-the-pyrdp-player)
    * [Playing a replay file](#playing-a-replay-file)
    * [Listening for live connections](#listening-for-live-connections)
    * [Changing the listening address](#changing-the-listening-address)
    * [Other player arguments](#other-player-arguments)
- [Using PyRDP as a Library](#using-pyrdp-as-a-library)
- [Contributing to PyRDP](#contributing-to-pyrdp)
- [Acknowledgements](#acknowledgements)

## Supported Systems
PyRDP should work on Python 3.6 and up.

This tool has been tested to work on Python 3.6 on Linux (Ubuntu 18.04). It has not been tested on OSX and Windows.

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

### Installing on Windows
If you want to install PyRDP on Windows, note that `setup.py` will try to compile `ext/rle.c`, so you will need to have
a C compiler installed. You will also need to generate a private key and certificate to run the MITM.

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

## Using the PyRDP Player
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

## Using the PyRDP Certificate Cloner
The PyRDP certificate cloner creates a brand new X509 certificate by using the values from an existing RDP server's
certificate. It connects to an RDP server, downloads its certificate, generates a new private key and replaces the
public key and signature of the certificate using the new private key. This can be used in a pentest if, for example,
you're trying to trick a legitimate user into going through your MITM. Using a certificate that looks like a legitimate
certificate could increase your success rate.

### Usage
You can clone a certificate by using `pyrdp-clonecert.py`:

```
pyrdp-clonecert.py 192.168.1.10 cert.pem -o key.pem
```

The `-o` parameter defines the path name to use for the generated private key.

### Using a custom private key
If you want to use your own private key instead of generating a new one:

```
pyrdp-clonecert.py 192.168.1.10 cert.pem -i input_key.pem
```

### Other cloner arguments
Run `pyrdp-clonecert.py --help` for a full list of arguments.

## Using PyRDP as a Library
If you're interested in experimenting with RDP and making your own tools, head over to our
[documentation section](docs/README.md) for more information.

## Contributing to PyRDP
See our [contribution guidelines](CONTRIBUTING.md).

## Acknowledgements
PyRDP uses code from the following open-source software:

- [RC4-Python](https://github.com/bozhu/RC4-Python) for the RC4 implementation.
- [rdesktop](https://github.com/rdesktop/rdesktop) for bitmap decompression.
- [rdpy](https://github.com/citronneur/rdpy) for RC4 keys, the bitmap decompression bindings and the base GUI code for
the PyRDP player.