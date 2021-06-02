## ProxyLogon

Original PoC: https://github.com/testanull
Inspired from the exploit of hausec: https://github.com/hausec

### How to use:

Use the pre-compiled binaries, or compile it by yourself. 

`nim c -d:ssl proxylogon.nim`

Linux version : 

`./proxylogon <name or IP of server> <user@fqdn> (<debug>) (<self>)`

### Example:

Windows version :

`.\proxylogon.exe 192.168.1.111 administrator@echo.lab self`

For windows version, do not forget to copy libssl and libcrypto ddls and cacert.pem in the good folder.

If successful you will be dropped into a webshell. `exit` or `quit` to escape from the webshell (or ctrl+c)

By default, it will create a file test.aspx. This can be changed.
