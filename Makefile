
EXES=client libevent-client libevent-server simpclt simpsvr rot13svr h2clt h2svr
# simpclt simpsvr rot13svr rot13svr2 rot13svr3

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
NGHTTP2=/opt/nghttp2-1.38.0
LIBEVENT=/usr/local/lib
OPENSSL=/usr/lib
endif
ifeq ($(UNAME_S),Darwin)
NGHTTP2=/Users/xixisun/work/29805546/nghttp2
LIBEVENT=/usr/local/Cellar/libevent/2.1.10
OPENSSL=/usr/local/Cellar/openssl/1.0.2s
endif

CC=cc
CFLAG=\
	-g -c -DHAVE_FCNTL_H -DHAVE_NETDB_H -DHAVE_UNISTD_H \
	-I$(NGHTTP2)/include
LDFLAG=\
   -L$(NGHTTP2)/lib -lnghttp2 \
   -ldl -pthread
LDFLAG2=\
   -L$(NGHTTP2)/lib -lnghttp2 \
   -L$(LIBEVENT)/lib -levent_openssl -levent \
   -L$(OPENSSL)/lib -lssl -lcrypto -ldl -pthread

all:	$(EXES)

http_parser.o: http-parser/http_parser.c
	$(CC) -c -g $<

cdecode.o: b64/cdecode.c
	$(CC) -c -g $<

cencode.o: b64/cencode.c
	$(CC) -c -g $<

log.o: log/log.c
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
libevent-server: libevent-server.o log.o
	$(CC) -o $@ $< log.o $(LDFLAG2)

h2clt.o: h2clt.c
	$(CC) $(CFLAG) $<
h2clt: h2clt.o http_parser.o cencode.o log.o
	$(CC) -o $@ $< http_parser.o cencode.o log.o $(LDFLAG)

h2svr.o: h2svr.c
	$(CC) $(CFLAG) $<
h2svr: h2svr.o http_parser.o log.o
	$(CC) -o $@ $< http_parser.o log.o $(LDFLAG)

simpclt.o: simpclt.c
	$(CC) $(CFLAG) $<
simpclt: simpclt.o
	$(CC) -o $@ $<

simpsvr.o: simpsvr.c
	$(CC) $(CFLAG) $<
simpsvr: simpsvr.o log.o
	$(CC) -o $@ $< log.o

rot13svr.o: rot13svr.c
	$(CC) $(CFLAG) $<
rot13svr: rot13svr.o log.o
	$(CC) -o $@ $< log.o

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
