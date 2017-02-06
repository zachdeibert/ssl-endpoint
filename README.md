# SSL Endpoint
`ssl-endpoint.exe` is a .NET application that acts as an SSL endpoint proxy.
It will run on all platforms (you can use `mono`).

# Usage
```
[mono] ssl-endpoint.exe [ssl host] [ssl port] [plain text host] [plain text port]
```
This will automatically detect if it needs to proxy from the plain text port or from the ssl port based on which ports are already bound.
If it cannot find a certificate or key pair, it will generate one itself.

## Examples
### Connect HTTP/HTTPS on localhost
```
[mono] ssl-endpoint.exe localhost 443 localhost 80
```
