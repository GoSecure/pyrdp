# PyRDP

Remote Desktop Protocol Man-in-the-Middle/library Python3.

- RDP Man-in-the-Middle (MITM)
- Live player to look at RDP connections through the MITM as they happen
- Replayer to look at RDP connections after they happened.

PyRDP uses some code from [RDPY](https://github.com/citronneur/rdpy) such as RC4 decryption, bitmap 
decompression and the base GUI for the Liveplayer/replayer.

PyRDP is fully implemented in Python,
except the bitmap decompression algorithm which is implemented in C for performance purposes.

### Dependencies

PyQt4 is needed for the liveplayer/replayer.
PyRDP has been tested to work on Python 3.6 on linux (Ubuntu). 
We have not tested it on OSX nor on Windows.

#### Linux

Example for Debian based systems :
```
sudo apt-get install python-qt4
```

#### OS X
Example for OS X to install PyQt with homebrew
```
$ brew install qt sip pyqt
```

#### Windows

x86 | x86_64
----|-------
[PyQt4](http://sourceforge.net/projects/pyqt/files/PyQt4/PyQt-4.11.3/PyQt4-4.11.3-gpl-Py2.7-Qt4.8.6-x32.exe) | [PyQt4](http://sourceforge.net/projects/pyqt/files/PyQt4/PyQt-4.11.3/PyQt4-4.11.3-gpl-Py2.7-Qt4.8.6-x64.exe/download)
[PyWin32](http://sourceforge.net/projects/pywin32/files/pywin32/Build%20218/pywin32-218.win32-py2.7.exe/download) | [PyWin32](http://sourceforge.net/projects/pywin32/files/pywin32/Build%20218/pywin32-218.win-amd64-py2.7.exe/download)

### Build

TODO

## PyRDP Binaries

- PyRDP MITM
- PyRDP Liveplayer/replayer

They are located in the bin/ folder of the project. Use `--help` to see how to use the programs.

## Contribution guidelines

1. Open an issue before starting your work;
2. Use Python3 type hinting whenever possible to remove ambiguity;
3. Document your methods and classes with docstrings using the reStructuredText syntax;
4. Respect PEP8 (except for the naming convention, use camelCase).
