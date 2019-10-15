// Server side C/C++ program to demonstrate Socket programming
#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#define PORT 8080

int main(int argc, char const *argv[]) {
  int server_fd, new_socket, valread;
  struct sockaddr_in address;
  int opt = 1;
  int addrlen = sizeof(address);
  char buffer[1024] = {0};
  char *hello = "Hello from server";

  // Creating socket file descriptor
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
    perror("socket failed");
    exit(EXIT_FAILURE);
  }

  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(PORT);

  // Forcefully attaching socket to the port 8080
  if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
    perror("bind failed");
    exit(EXIT_FAILURE);
  }

  if (listen(server_fd, 3) < 0) {
    perror("listen");
    exit(EXIT_FAILURE);
  }

  if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
    perror("accept");
    exit(EXIT_FAILURE);
  }

  valread = read(new_socket, buffer, 1024);
  printf("%s\n",buffer);

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

  send(new_socket, buf1, sizeof(buf1), 0);
  printf("Hello message sent\n");

  close(new_socket);

  return 0;
}
