
1. create ssl/tls private key and certificate files.
$ openssl
> genrsa -des3 -out server.key 1024	# needs to set "pass phrase"
> req -new -key server.key -sha256 -out server.csr
> x509 -req -days 365 -in server.csr -signkey server.key -sha256 -out server.crt

2. build
$ make	# per original offical Makefile by using like "make --just-print" 

3. start server
$ libevent-server 12978 server.key server.crt	# waiting for client after "pass phrase" 
Enter PEM pass phrase:
::ffff:127.0.0.1 connected
::ffff:127.0.0.1 GET /
::ffff:127.0.0.1 EOF
::ffff:127.0.0.1 disconnected

4. start client from another terminal
$ libevent-client https://localhost:12978/; echo
Connected
Request headers:
:method: GET
:scheme: https
:authority: localhost:12978
:path: /

Response headers for stream ID=1:
:status: 404
All headers received
Stream 1 closed with error_code=0
<html><head><title>404</title></head><body><h1>404 Not Found</h1></body></html>


h2c client / server sample
$ make h2clt h2svr
$ h2svr 12978 /style.css		# start server (optionally push file style.css)
$ h2clt http://localhost:12978/ # start client from another terminal (need setenv as well)
