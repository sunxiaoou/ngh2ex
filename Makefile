
EXES=client libevent-client libevent-server h2evclt h2evsvr
# simpclt simpsvr rot13svr rot13svr2 rot13svr3

CC=cc
CFLAG=-g -c -DHAVE_FCNTL_H -DHAVE_NETDB_H -DHAVE_UNISTD_H
LDFLAG=\
   -L/Users/xixisun/work/29805546/nghttp2/lib -lnghttp2 \
   -L/usr/local/Cellar/libevent/2.1.10/lib -levent \
   -ldl -pthread
LDFLAG2=\
   -L/Users/xixisun/work/29805546/nghttp2/lib -lnghttp2 \
   -L/usr/local/Cellar/libevent/2.1.10/lib -levent_openssl -levent \
   -L/usr/local/Cellar/openssl/1.0.2s/lib -lssl -lcrypto -ldl -pthread

all:	$(EXES)

http_parser.o: http-parser/http_parser.c
	$(CC) -c -g $<

cdecode.o: b64/cdecode.c
	$(CC) -c -g $<

cencode.o: b64/cencode.c
	$(CC) -c -g $<

client.o: client.c
	$(CC) $(CFLAG) $<
client: client.o http_parser.o
	$(CC) -o $@ $< http_parser.o $(LDFLAG2)

libevent-client.o: libevent-client.c
	$(CC) $(CFLAG) $<
libevent-client: libevent-client.o http_parser.o
	$(CC) -o $@ $< http_parser.o $(LDFLAG2)

libevent-server.o: libevent-server.c
	$(CC) $(CFLAG) $<
libevent-server: libevent-server.o
	$(CC) -o $@ $< $(LDFLAG2)  

h2evclt.o: h2evclt.c
	$(CC) $(CFLAG) $<
h2evclt: h2evclt.o http_parser.o cencode.o
	$(CC) -o $@ $< http_parser.o cencode.o $(LDFLAG)

h2evsvr.o: h2evsvr.c
	$(CC) $(CFLAG) $<
h2evsvr: h2evsvr.o
	$(CC) -o $@ $< $(LDFLAG)

simpclt.o: simpclt.c
	$(CC) $(CFLAG) $<
simpclt: simpclt.o
	$(CC) -o $@ $<

simpsvr.o: simpsvr.c
	$(CC) $(CFLAG) $<
simpsvr: simpsvr.o
	$(CC) -o $@ $<

rot13svr.o: rot13svr.c
	$(CC) $(CFLAG) $<
rot13svr: rot13svr.o
	$(CC) -o $@ $<

rot13svr2.o: rot13svr2.c
	$(CC) $(CFLAG) $<
rot13svr2: rot13svr2.o
	$(CC) -o $@ $< $(LDFLAG)

rot13svr3.o: rot13svr3.c
	$(CC) $(CFLAG) $<
rot13svr3: rot13svr3.o
	$(CC) -o $@ $< $(LDFLAG)

clean:
	rm -f *.o $(EXES)
