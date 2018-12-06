# PyRDP

PyRDP is a Python3 Remote Desktop Protocol (RDP) Man-in-the-Middle (MITM) and library to experiment with RDP.

It has two main tools:
- RDP Man-in-the-Middle (MITM)
- RDP Player:
    - Live player to look at RDP connections through the MITM as they happen
    - Replayer to look at RDP connections after they happened from a file

PyRDP uses some code from [RDPY](https://github.com/citronneur/rdpy) such as RC4 decryption, bitmap 
decompression and the base GUI for the PyRDP Player.

PyRDP is fully implemented in Python,
except for the bitmap decompression algorithm which is implemented in C for performance purposes.

### Dependencies

PyQt4 is needed for the liveplayer/replayer.
```
sudo apt install python3-pyqt4
```
As for the other python dependencies, take a look at `setup.py` (`install_requires`).
 
PyRDP has been tested to work on Python 3.6 on linux (Ubuntu 18.04). 
We have not tested it on OSX nor on Windows.


## PyRDP Binaries

- PyRDP MITM
- PyRDP Liveplayer/replayer

They are located in the bin/ folder of the project. Use `--help` to see how to use the programs.

## Contribution guidelines

1. Open an issue before starting your work;
2. Use Python3 type hinting whenever possible to remove ambiguity;

    2.1. If you come across restructuredText type hinting (such us `:type param1: str`), please change it to Python 3 type hinting `def function1(param1: str)`
3. Document your methods and classes with docstrings using the reStructuredText syntax;
4. Respect PEP8 (except for the naming convention, use camelCase).
5. Whenever possible, use format strings (`f"My variable: {myVariable}"`) instead of %-style formating or `str.format()`