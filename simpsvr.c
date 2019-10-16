// Server side C/C++ program to demonstrate Socket programming
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

#include "log/log.h"

#define PORT 8080

int listen_to(int port, int nlisten) {
	PRINT(log_in, "listen_to")

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (socket < 0) {
		perror("socket failed");
		PRINT(log_out, "listen_to")
    return -1;
	}
	
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);

	int rc = bind(sock, (struct sockaddr *)(&sin), sizeof(struct sockaddr_in));
	if (rc < 0) {
    perror("bind failed");
		close(sock);
    PRINT(log_out, "listen_to2")
		return -1;
	}

	rc = listen(sock, nlisten);
	if (rc < 0) {
    perror("listen failed");
		close(sock);
    PRINT(log_out, "listen_to3")
		return -1;
	}

  PRINT(log_out, "listen_to4")
	return sock;
}

int accept_to(int listener) {
  PRINT(log_in, "accept_to")

	struct sockaddr_in sin;
	unsigned long len = sizeof(struct sockaddr_in);
	int sock = accept(listener, (struct sockaddr *)(&sin), (socklen_t *)&len);
	if (sock < 0) {
    perror("accept");
    PRINT(log_out, "accept_to")
    return -1;
	}

  PRINT(log_out, "accept_to2")
	return sock;
}

int main(int argc, char const *argv[]) {
  PRINT(log_in, "main")

  int listener = listen_to(PORT, 3);
  if (listener < 0) {
    PRINT(log_out, "main")
    return -1;
  }

  int sock = accept_to(listener);
  if (sock < 0) {
    PRINT(log_out, "main2")
    return -1;
  }

  char buffer[1024] = {0};
  int len = read(sock, buffer, 1024);
  HEXDUMP(buffer, len)
  fprintf(stderr, "read(%d)\n", len);

  char buf1[] = {
    0X48, 0X54, 0X54, 0X50, 0X2F, 0X31, 0X2E, 0X31, 0X20, 0X31, 0X30, 0X31, 0X20, 0X53, 0X77, 0X69,
    0X74, 0X63, 0X68, 0X69, 0X6E, 0X67, 0X20, 0X50, 0X72, 0X6F, 0X74, 0X6F, 0X63, 0X6F, 0X6C, 0X73,
    0X0D, 0X0A, 0X43, 0X6F, 0X6E, 0X6E, 0X65, 0X63, 0X74, 0X69, 0X6F, 0X6E, 0X3A, 0X20, 0X55, 0X70,
    0X67, 0X72, 0X61, 0X64, 0X65, 0X0D, 0X0A, 0X44, 0X61, 0X74, 0X65, 0X3A, 0X20, 0X54, 0X75, 0X65,
    0X2C, 0X20, 0X31, 0X35, 0X20, 0X4F, 0X63, 0X74, 0X20, 0X32, 0X30, 0X31, 0X39, 0X20, 0X30, 0X36,
    0X3A, 0X32, 0X34, 0X3A, 0X30, 0X33, 0X20, 0X47, 0X4D, 0X54, 0X0D, 0X0A, 0X43, 0X6F, 0X6E, 0X74,
    0X65, 0X6E, 0X74, 0X2D, 0X4C, 0X65, 0X6E, 0X67, 0X74, 0X68, 0X3A, 0X20, 0X30, 0X0D, 0X0A, 0X58,
    0X2D, 0X4F, 0X52, 0X41, 0X43, 0X4C, 0X45, 0X2D, 0X44, 0X4D, 0X53, 0X2D, 0X52, 0X49, 0X44, 0X3A,
    0X20, 0X30, 0X0D, 0X0A, 0X55, 0X70, 0X67, 0X72, 0X61, 0X64, 0X65, 0X3A, 0X20, 0X68, 0X32, 0X63,
    0X0D, 0X0A, 0X58, 0X2D, 0X4F, 0X52, 0X41, 0X43, 0X4C, 0X45, 0X2D, 0X44, 0X4D, 0X53, 0X2D, 0X45,
    0X43, 0X49, 0X44, 0X3A, 0X20, 0X61, 0X37, 0X33, 0X32, 0X63, 0X38, 0X32, 0X31, 0X2D, 0X61, 0X66,
    0X32, 0X39, 0X2D, 0X34, 0X33, 0X64, 0X31, 0X2D, 0X38, 0X38, 0X32, 0X30, 0X2D, 0X38, 0X31, 0X34,
    0X61, 0X32, 0X62, 0X66, 0X38, 0X35, 0X65, 0X64, 0X65, 0X2D, 0X30, 0X30, 0X30, 0X30, 0X30, 0X30,
    0X32, 0X66, 0X0D, 0X0A, 0X0D, 0X0A
  };

  HEXDUMP(buf1, sizeof(buf1))
  len = write(sock, buf1, sizeof(buf1));
  fprintf(stderr, "written(%d)\n", len);

  close(sock);

  PRINT(log_out, "main3")
  return 0;
}
