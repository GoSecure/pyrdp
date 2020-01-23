# PyRDP
PyRDP is a Python 3 Remote Desktop Protocol (RDP) Man-in-the-Middle (MITM) and library.

![PyRDP Logo](https://raw.githubusercontent.com/GoSecure/pyrdp/master/docs/pyrdp-logo.svg?sanitize=true)

It features a few tools:
- RDP Man-in-the-Middle
    - Logs credentials used when connecting
    - Steals data copied to the clipboard
    - Saves a copy of the files transferred over the network
    - Crawls shared drives in the background and saves them locally
    - Saves replays of connections so you can look at them later
    - Runs console commands or PowerShell payloads automatically on new connections
- RDP Player:
    - See live RDP connections coming from the MITM
    - View replays of RDP connections
    - Take control of active RDP sessions while hiding your actions
    - List the client's mapped drives and download files from them during active sessions
- RDP Certificate Cloner:
    - Create a self-signed X509 certificate with the same fields as an RDP server's certificate

We have used this tool as part of an RDP honeypot which records sessions and saves a copy of the malware dropped on our
target machine.

PyRDP was [first introduced in a blogpost](https://www.gosecure.net/blog/2018/12/19/rdp-man-in-the-middle-smile-youre-on-camera) in which we [demonstrated that we can catch a real threat actor in action](https://www.youtube.com/watch?v=eB7RC9FmL6Q). In May 2019 a [presentation by its authors](https://docs.google.com/presentation/d/1avcn8Sh2b3IE7AA0G9l7Cj5F1pxqizUm98IbXUo2cvY/edit#slide=id.g404b70030f_0_581) was given at NorthSec and two demos were performed. [The first one covered](https://youtu.be/5JztJzi-m48) credential logging, clipboard stealing, client-side file browsing and a session take-over. [The second one covered](https://youtu.be/bU67tj1RkMA) the execution of cmd or powershell payloads when a client successfully authenticates.
In August 2019, PyRDP was demo'ed at BlackHat Arsenal ([slides](https://docs.google.com/presentation/d/17P_l2n-hgCehQ5eTWilru4IXXHnGIRTj4ftoW4BiX5A/edit?usp=sharing)).

## Table of Contents
- [Supported Systems](#supported-systems)
- [Installing](#installing)
  * [Using the Docker Image](#using-the-docker-image)
  * [From Git Source](#from-git-source)
  * [Installing on Windows](#installing-on-windows)
  * [Building the Docker Image](#building-the-docker-image)
  * [Migrating away from pycrypto](#migrating-away-from-pycrypto)
- [Using PyRDP](#using-pyrdp)
  * [Using the PyRDP Man-in-the-Middle](#using-the-pyrdp-man-in-the-middle)
    + [Specifying the private key and certificate](#specifying-the-private-key-and-certificate)
    + [Connecting to the PyRDP player](#connecting-to-the-pyrdp-player)
      - [Connecting to a PyRDP player when the MITM is running on a server](#connecting-to-a-pyrdp-player-when-the-mitm-is-running-on-a-server)
    + [Running payloads on new connections](#running-payloads-on-new-connections)
      - [Setting the payload](#setting-the-payload)
      - [Choosing when to start the payload](#choosing-when-to-start-the-payload)
      - [Choosing when to resume normal activity](#choosing-when-to-resume-normal-activity)
    + [Other MITM arguments](#other-mitm-arguments)
  * [Using the PyRDP Player](#using-the-pyrdp-player)
    + [Playing a replay file](#playing-a-replay-file)
    + [Listening for live connections](#listening-for-live-connections)
    + [Changing the listening address](#changing-the-listening-address)
    + [Other player arguments](#other-player-arguments)
  * [Using the PyRDP Certificate Cloner](#using-the-pyrdp-certificate-cloner)
    + [Cloning a certificate](#cloning-a-certificate)
    + [Using a custom private key](#using-a-custom-private-key)
    + [Other cloner arguments](#other-cloner-arguments)
  * [Using PyRDP as a Library](#using-pyrdp-as-a-library)
  * [Using PyRDP with twistd](#using-pyrdp-with-twistd)
  * [Using PyRDP with Bettercap](#using-pyrdp-with-bettercap)
  * [Docker Specific Usage Instructions](#docker-specific-usage-instructions)
    + [Mapping a Listening Port](#mapping-a-listening-port)
    + [Logs and Artifacts Storage](#logs-and-artifacts-storage)
    + [Using the GUI Player in Docker](#using-the-gui-player-in-docker)
- [PyRDP Presentations](#pyrdp-presentations)
- [Contributing to PyRDP](#contributing-to-pyrdp)
- [Acknowledgements](#acknowledgements)


## Supported Systems
PyRDP should work on Python 3.6 and up.

This tool has been tested to work on Python 3.6 on Linux (Ubuntu 18.04) and Windows (See section [Installing on Windows](#installing-on-windows)). It has not been tested on OSX.

## Installing

_Note: PyRDP cannot be installed on 32bit systems. See: [this issue.](https://github.com/GoSecure/pyrdp/issues/150)_

### Using the Docker Image

This is the easiest installation method if you have docker installed and working.

```
docker pull gosecure/pyrdp:latest
```

### From Git Source

We recommend installing PyRDP in a
[virtual environment](https://packaging.python.org/guides/installing-using-pip-and-virtual-environments/)
to avoid dependency issues.

First, make sure to install the prerequisite packages (on Ubuntu):

```
sudo apt install libdbus-1-dev libdbus-glib-1-dev libgl1-mesa-glx git python3-dev
```

On some systems, you may need to install the `python3-venv` package:

```
sudo apt install python3-venv
```

Grab PyRDP's source code:

```
git clone https://github.com/gosecure/pyrdp.git
```

Then, create your virtual environment in the `venv` directory inside PyRDP's directory:

```
cd pyrdp 
python3 -m venv venv
```

*DO NOT* use the root PyRDP directory for the virtual environment folder (`python3 -m venv .`). You will make a mess,
and using a directory name like `venv` is more standard anyway.

Before installing the dependencies, you need to activate your virtual environment:

```
source venv/bin/activate
```

Finally, you can install the project with Pip:

```
pip3 install -U pip setuptools wheel
pip3 install -U -e .
```

This should install all the dependencies required to run PyRDP.

If you ever want to leave your virtual environment, you can simply deactivate it:

```
deactivate
```

Note that you will have to activate your environment every time you want to have the PyRDP scripts available as shell
commands.

### Installing on Windows

The steps are almost the same. There are two additional prerequisites.

1. Any C compiler
2. [OpenSSL](https://wiki.openssl.org/index.php/Binaries). Make sure it is reachable from your `$PATH`.

Then, create your virtual environment in PyRDP's directory:

```
cd pyrdp
python3 -m venv venv
```

*DO NOT* use the root PyRDP directory for the virtual environment folder (`python3 -m venv .`). You will make a mess,
and using a directory name like `venv` is more standard anyway.

Before installing the dependencies, you need to activate your virtual environment:

```
venv\Scripts\activate
```

Finally, you can install the project with Pip:

```
pip3 install -U pip setuptools wheel
pip3 install -U -e .
```

This should install all the dependencies required to run PyRDP.

If you ever want to leave your virtual environment, you can simply deactivate it:

```
deactivate
```

Note that you will have to activate your environment every time you want to have the PyRDP scripts available as shell
commands.

### Building the Docker Image

First of all, build the image by executing this command at the root of PyRDP (where Dockerfile is located):

```
docker build -t pyrdp .
```

Afterwards, you can execute PyRDP by invoking the `pyrdp` docker container. See [Usage instructions](#using-pyrdp) and the [Docker specific instructions](#docker-specific-usage-instructions) for details.

### Migrating away from pycrypto
Since pycrypto isn't maintained anymore, we chose to migrate to pycryptodome.
If you get this error, it means that you are using the module pycrypto instead of pycryptodome.

```
[...]
  File "[...]/pyrdp/pyrdp/pdu/rdp/connection.py", line 10, in <module>
    from Crypto.PublicKey.RSA import RsaKey
ImportError: cannot import name 'RsaKey'
```

You will need to remove the module pycrypto and reinstall PyRDP.

```
pip3 uninstall pycrypto
pip3 install -U -e .
```

## Using PyRDP

### Using the PyRDP Man-in-the-Middle
Use `pyrdp-mitm.py <ServerIP>` or `pyrdp-mitm.py <ServerIP>:<ServerPort>` to run the MITM.

Assuming you have an RDP server running on `192.168.1.10` and listening on port 3389, you would run:

```
pyrdp-mitm.py 192.168.1.10
```

When running the MITM for the first time on Linux, a private key and certificate should be generated for you in `~/.config/pyrdp`.
These are used when TLS security is used on a connection. You can use them to decrypt PyRDP traffic in Wireshark, for
example.

#### Specifying the private key and certificate
If key generation didn't work or you want to use a custom key and certificate, you can specify them using the
`-c` and `-k` arguments:

```
pyrdp-mitm.py 192.168.1.10 -k private_key.pem -c certificate.pem
``` 

#### Connecting to the PyRDP player
If you want to see live RDP connections through the PyRDP player, you will need to specify the ip and port on which the
player is listening using the `-i` and `-d` arguments. Note: the port argument is optional, the default port is 3000.

```
pyrdp-mitm.py 192.168.1.10 -i 127.0.0.1 -d 3000
```

##### Connecting to a PyRDP player when the MITM is running on a server
If you are running the MITM on a server and still want to see live RDP connections, you should use
[SSH remote port forwarding](https://www.booleanworld.com/guide-ssh-port-forwarding-tunnelling/)
to forward a port on your server to the player's port on your machine. Once this is done, you pass `127.0.0.1` and the forwarded
port as arguments to the MITM. For example, if port 4000 on the server is forwarded to the player's port on your machine,
this would be the command to use:

```
pyrdp-mitm.py 192.168.1.10 -i 127.0.0.1 -d 4000
```

#### Running payloads on new connections
PyRDP has support for running console commands or PowerShell payloads automatically when new connections are made.
Due to the nature of RDP, the process is a bit hackish and is not always 100% reliable. Here is how it works:

1. Wait for the user to be authenticated.
2. Block the client's input / output to hide the payload and prevent interference.
3. Send a fake Windows+R sequence and run `cmd.exe`.
4. Run the payload as a console command and exit the console. If a PowerShell payload is configured, it is run with `powershell -enc <PAYLOAD>`.
5. Wait a bit to allow the payload to complete.
6. Restore the client's input / output.

For this to work, you need to set 3 arguments:

- the payload
- the delay before the payload starts
- the payload's duration

##### Setting the payload
You can use one of the following arguments to set the payload to run:

- `--payload`, a string containing console commands
- `--payload-powershell`, a string containing PowerShell commands
- `--payload-powershell-file`, a path to a PowerShell script

##### Choosing when to start the payload
For the moment, PyRDP does not detect when the user is logged on.
You must give it an amount of time to wait for before running the payload.
After this amount of time has passed, it will send the fake key sequences and expect the payload to run properly.
To do this, you use the `--payload-delay` argument. The delay is in milliseconds.
For example, if you expect the user to be logged in within the first 5 seconds, you would use the following arguments:

```
--payload-delay 5000
```

This could be made more accurate by leveraging some messages exchanged during RDPDR initialization.
See [this issue](https://github.com/GoSecure/pyrdp/issues/98) if you're interested in making this work better.

##### Choosing when to resume normal activity
Because there is no direct way to know when the console has stopped running, you must tell PyRDP how long you want
the client's input / output to be blocked. We recommend you set this to the maximum amount of time you would expect the
console that is running your payload to be visible. In other words, the amount of time you would expect your payload to
complete.
To set the payload duration, you use the `--payload-duration` argument with an amount of time in milliseconds.
For example, if you expect your payload to take up to 5 seconds to complete, you would use the following argument:

```
--payload-duration 5000
```

This will block the client's input / output for 5 seconds to hide the console and prevent interference.
After 5 seconds, input / output is restored back to normal.

#### Other MITM arguments
Run `pyrdp-mitm.py --help` for a full list of arguments.

### Using the PyRDP Player
Use `pyrdp-player.py` to run the player.

#### Playing a replay file
You can use the menu to open a new replay file: File > Open.

You can also open replay files when launching the player:

```
pyrdp-player.py <FILE1> <FILE2> ...
```

#### Listening for live connections
The player always listens for live connections. By default, the listening port is 3000, but it can be changed:

```
pyrdp-player.py -p <PORT>
``` 

#### Changing the listening address
By default, the player only listens to connections coming from the local machine. We do not recommend opening up the player
to other machines. If you still want to change the listening address, you can do it with `-b`:

```
pyrdp-player.py -b <ADDRESS>
```

#### Other player arguments
Run `pyrdp-player.py --help` for a full list of arguments.

### Using the PyRDP Certificate Cloner
The PyRDP certificate cloner creates a brand new X509 certificate by using the values from an existing RDP server's
certificate. It connects to an RDP server, downloads its certificate, generates a new private key and replaces the
public key and signature of the certificate using the new private key. This can be used in a pentest if, for example,
you're trying to trick a legitimate user into going through your MITM. Using a certificate that looks like a legitimate
certificate could increase your success rate.

#### Cloning a certificate
You can clone a certificate by using `pyrdp-clonecert.py`:

```
pyrdp-clonecert.py 192.168.1.10 cert.pem -o key.pem
```

The `-o` parameter defines the path name to use for the generated private key.

#### Using a custom private key
If you want to use your own private key instead of generating a new one:

```
pyrdp-clonecert.py 192.168.1.10 cert.pem -i input_key.pem
```

#### Other cloner arguments
Run `pyrdp-clonecert.py --help` for a full list of arguments.

### Using PyRDP as a Library
If you're interested in experimenting with RDP and making your own tools, head over to our
[documentation section](docs/README.md) for more information.

### Using PyRDP with twistd
The PyRDP MITM component was also implemented as a twistd plugin. This enables
you to run it in debug mode and allows you to get an interactive debugging repl
(pdb) if you send a `SIGUSR2` to the twistd process.

```
twistd --debug pyrdp -t <target>
```

Then to get the repl:

```
killall -SIGUSR2 twistd
```

### Using PyRDP with twistd in Docker
In a directory with our `docker-compose.yml` you can run something like this:

```
docker-compose run -p 3389:3389 pyrdp twistd --debug pyrdp --target 192.168.1.10:3389
```

This will allocate a TTY and you will have access to `Pdb`'s REPL. Trying to add `--debug` to the `docker-compose.yml` command will fail because there is no TTY allocated.

### Using PyRDP with Bettercap
We developped our own Bettercap module, `rdp.proxy`, to man-in-the-middle all RDP connections
on a given LAN. Check out [this document](docs/bettercap-rdp-mitm.md) for more information.

### Docker Specific Usage Instructions

Since docker restricts the interactions with the host system (filesystem and network), the PyRDP docker image must be run with some parameters depending on your use case. This section documents those parameters.

We refer to the publicly provided docker image but if you [built your own](#building-the-docker-image) replace `gosecure/pyrdp` with the name of your locally built image.

#### Mapping a Listening Port

In most of the man-in-the-middle cases you will need to map a port of your host into the docker image. This is achieved by the `--publish` (`-p`) parameters applied to `docker run`.

For example, to listen on 3389 (RDP's default port) on all interfaces, use:

```
docker run -p 3389:3389 gosecure/pyrdp pyrdp-mitm.py 192.168.1.10
```

#### Logs and Artifacts Storage

To store the PyRDP output permanently (logs, files, etc.), add the `--volume` (`-v`) option to the previous command. In this example we store the files relatively to the current directory in `pyrdp_output`:

```
docker run -v $PWD/pyrdp_output:/home/pyrdp/pyrdp_output -p 3389:3389 gosecure/pyrdp pyrdp-mitm.py 192.168.1.10
```

Make sure that your destination directory is owned by a user with a UID of 1000, otherwise you will get permission denied errors.
If you are the only non-root user on the system, usually your user will be assigned UID 1000.

#### Using the GUI Player in Docker

Using the player will require you to export the `DISPLAY` environment variable from the host to the docker.
This redirects the GUI of the player to the host screen.
You also need to expose the host's network and prevent Qt from using the MIT-SHM X11 Shared Memory Extension.
To do so, add the `-e` and `--net` options to the run command:

```
docker run -e DISPLAY=$DISPLAY -e QT_X11_NO_MITSHM=1 --net=host gosecure/pyrdp pyrdp-player.py
```

Keep in mind that exposing the host's network to docker can compromise the isolation between your container and the host.
If you plan on using the player, X11 forwarding using an SSH connection would be a more secure way.


## PyRDP Presentations

## Contributing to PyRDP
See our [contribution guidelines](CONTRIBUTING.md).

## Acknowledgements
PyRDP uses code from the following open-source software:

- [RC4-Python](https://github.com/bozhu/RC4-Python) for the RC4 implementation.
- [rdesktop](https://github.com/rdesktop/rdesktop) for bitmap decompression.
- [rdpy](https://github.com/citronneur/rdpy) for RC4 keys, the bitmap decompression bindings and the base GUI code for
the PyRDP player.
- [FreeRDP](https://github.com/FreeRDP/FreeRDP) for the scan code enumeration.
