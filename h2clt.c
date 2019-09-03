// Client side C/C++ program to demonstrate Socket programming
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include <nghttp2/nghttp2.h>

#include "b64/cencode.h"

#define PORT 7001

void log_data(unsigned char *data, int len)
{
	unsigned char c;
	char tmbuf[40];
	int i, j, maxlen;

  fprintf(stderr, "len(%d)\n", len);
  for(i = 0; i < len;){
    fprintf(stderr, "%03x | ", i / 16);
    maxlen = (len - i > 16) ? 16 : len - i;
    for(j = 0; j < maxlen; j ++){
      if(j && j % 4 == 0)
        fprintf(stderr, " ");
      fprintf(stderr, "%02X", *((unsigned char *)data + i + j));
    }

    for(; j < 16; j ++){
      if(j && j % 4 == 0)
        fprintf(stderr, " ");
      fprintf(stderr, "  ");
    }

    fprintf(stderr, " | ");
    for(j = 0; j < maxlen; j ++) {
      c = *((unsigned char *)data + i + j);
      if(c >= ' ' && c < 127 )
        fprintf(stderr, "%c", c);
      else
        fprintf(stderr, ".");
    }
    for(; j < 16; j ++)
      fprintf(stderr, " ");

    i += maxlen;
    if(i < len)
      fprintf(stderr, "\n");
  }

  fprintf(stderr, "\n");
}

void make_upgrade_str(char *buf) {
  nghttp2_settings_entry iv[1] = {
	   {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  uint8_t settings_payload[128];
  char b64[128];
  rv = nghttp2_pack_settings_payload(settings_payload, sizeof(settings_payload), iv, 1);
  if (rv <= 0) {
    printf("Could not pack SETTINGS: %s", nghttp2_strerror(rv));
  }

  char *c = b64;
  int cnt = 0;
  base64_encodestate s;

  base64_init_encodestate(&s);
  cnt = base64_encode_block((char *)settings_payload, rv, c, &s);
  c += cnt;
  cnt = base64_encode_blockend(c, &s);
  // c += cnt;
  *c = 0;

  c = buf;
  cnt = sprintf(c, "%s %s HTTP/1.1\r\n", "GET", "/svlt29805546");
  c += cnt;
  cnt = sprintf(c, "host: %s\r\n", "slc09wsz.us.oracle.com:7001");
  c += cnt;
  cnt = sprintf(c, "connection: Upgrade, HTTP2-Settings\r\n");
  c += cnt;
  cnt = sprintf(c, "upgrade: %s\r\n", NGHTTP2_CLEARTEXT_PROTO_VERSION_ID);
  c += cnt;
  cnt = sprintf(c, "http2-settings: %s\r\n", b64);
  c += cnt;
  cnt = sprintf(c, "accept: */*\r\n");
  c += cnt;
  cnt = sprintf(c, "user-agent: nghttp2/%s\r\n\r\n", NGHTTP2_VERSION);
  c += cnt;
  *c = 0;
}

int main(int argc, char const *argv[])
{
  int sock = 0, valread;
  struct sockaddr_in serv_addr;
  char *hello = "Hello from client";
  char buffer[1024] = {0};
  if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Socket creation error \n");
    return -1;
  }

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(PORT);
  
  // Convert IPv4 and IPv6 addresses from text to binary form
  if (inet_pton(AF_INET, "10.245.251.228", &serv_addr.sin_addr) <= 0) {
    printf("\nInvalid address/ Address not supported \n");
    return -1;
  }

  if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("\nConnection Failed \n");
    return -1;
  }

  /*
  static unsigned char sbuf[] = {
    0x47, 0x45, 0x54, 0x20, 0x2f, 0x73, 0x76, 0x6c, 0x74, 0x32, 0x39, 0x38, 0x30, 0x35, 0x35, 0x34,
    0x36, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x68, 0x6f, 0x73, 0x74,
    0x3a, 0x20, 0x73, 0x6c, 0x63, 0x30, 0x39, 0x77, 0x73, 0x7a, 0x2e, 0x75, 0x73, 0x2e, 0x6f, 0x72,
    0x61, 0x63, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x3a, 0x37, 0x30, 0x30, 0x31, 0x0d, 0x0a, 0x63,
    0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x3a, 0x20, 0x55, 0x70, 0x67, 0x72, 0x61,
    0x64, 0x65, 0x2c, 0x20, 0x48, 0x54, 0x54, 0x50, 0x32, 0x2d, 0x53, 0x65, 0x74, 0x74, 0x69, 0x6e,
    0x67, 0x73, 0x0d, 0x0a, 0x75, 0x70, 0x67, 0x72, 0x61, 0x64, 0x65, 0x3a, 0x20, 0x68, 0x32, 0x63,
    0x0d, 0x0a, 0x68, 0x74, 0x74, 0x70, 0x32, 0x2d, 0x73, 0x65, 0x74, 0x74, 0x69, 0x6e, 0x67, 0x73,
    0x3a, 0x20, 0x41, 0x41, 0x4d, 0x41, 0x41, 0x41, 0x42, 0x6b, 0x41, 0x41, 0x51, 0x41, 0x41, 0x50,
    0x5f, 0x5f, 0x0d, 0x0a, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d,
    0x0a, 0x75, 0x73, 0x65, 0x72, 0x2d, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x6e, 0x67, 0x68,
    0x74, 0x74, 0x70, 0x32, 0x2f, 0x31, 0x2e, 0x33, 0x38, 0x2e, 0x30, 0x0d, 0x0a, 0x0d, 0x0a
  };

  log_data(sbuf, sizeof(sbuf));
  */

  char buf[1024];
  make_upgrade_str(buf);
  log_data((unsigned char *)buf, strlen(buf));
  int rc = write(sock, buf, strlen(buf));
  printf("writen(%d)\n", rc);

  rc = read(sock, (unsigned char *)buffer, sizeof(buffer));
  printf("read(%d)\n", rc);

  static unsigned char buf2[] = {
    0x50, 0x52, 0x49, 0x20, 0x2a, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x32, 0x2e, 0x30, 0x0d, 0x0a,
    0x0d, 0x0a, 0x53, 0x4d, 0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x00, 0x0c, 0x04, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x64, 0x00, 0x04, 0x00, 0x00, 0xff, 0xff    
  };
  rc = write(sock, buf2, sizeof(buf2));
  printf("writen(%d)\n", rc);

  rc = read(sock, (unsigned char *)buffer, sizeof(buffer));
  printf("read(%d)\n", rc);

  static unsigned char buf3[] = {
    0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00
  };
  rc = write(sock, buf3, sizeof(buf3));
  printf("writen(%d)\n", rc);

  int i;
  for (i = 0; i < 4; i ++) {
    rc = read(sock, (unsigned char *)buffer, sizeof(buffer));
    printf("read(%d)\n", rc);
  }

  return 0;
}
