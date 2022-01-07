# Legacy Documentation

Some legacy documentation kept around just in case it proves useful.


## Migrating away from pycrypto

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