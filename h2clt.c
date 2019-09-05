// Client side C/C++ program to demonstrate Socket programming
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <nghttp2/nghttp2.h>

#include "http-parser/http_parser.h"
#include "b64/cencode.h"

int Indent = 0;

typedef struct {
  int sock;
  int stream_id;
  nghttp2_session *session;
} http2_session_data;

static void log_data(unsigned char *data, int len)
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

static int connect_to(const char *host, uint16_t port) {
  struct addrinfo hints;
  int fd = -1;
  int rv;
  char service[NI_MAXSERV];
  struct addrinfo *res, *rp;

  snprintf(service, sizeof(service), "%u", port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  rv = getaddrinfo(host, service, &hints, &res);
  if (rv != 0) {
	  fprintf(stderr, "FATAL: getaddrinfo: %s\n", gai_strerror(rv));
	  return -1;
  }
  for (rp = res; rp; rp = rp->ai_next) {
    fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd == -1) {
      continue;
    }
    while ((rv = connect(fd, rp->ai_addr, rp->ai_addrlen)) == -1 && errno == EINTR)
      ;
    if (rv == 0) {
      break;
    }
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}

static void make_upgrade_request(char *buf, unsigned char *settings, int slen, char *host, int port,
    char *path) {
  fprintf(stderr, "%*c{ make_upgrade_request\n", 2 * Indent ++, ' ');

  char b64[128];
  char *c = b64;
  int cnt = 0;
  base64_encodestate s;

  base64_init_encodestate(&s);
  cnt = base64_encode_block((char *)settings, slen, c, &s);
  c += cnt;
  cnt = base64_encode_blockend(c, &s);
  // c += cnt;
  *c = 0;

  c = buf;
  cnt = sprintf(c, "%s %s HTTP/1.1\r\n", "GET", path);
  c += cnt;
  cnt = sprintf(c, "host: %s:%d\r\n", host, port);
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

  fprintf(stderr, "%*c} make_upgrade_request\n", 2 * -- Indent, ' ');
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
  fprintf(stderr, "%*c{ send_callback\n", 2 * Indent ++, ' ');

  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;
  (void)flags;

  log_data((unsigned char *)data, length);
  // bufferevent_write(bev, data, length);

  fprintf(stderr, "%*c} send_callback\n", 2 * -- Indent, ' ');
  return (ssize_t)length;
}

static void print_header(FILE *f, const uint8_t *name, size_t namelen,
                         const uint8_t *value, size_t valuelen) {
  fwrite(name, 1, namelen, f);
  fprintf(f, ": ");
  fwrite(value, 1, valuelen, f);
  fprintf(f, "\n");
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  fprintf(stderr, "%*c{ on_header_callback\n", 2 * Indent ++, ' ');
  
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;
  (void)flags;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE && session_data->stream_id == frame->hd.stream_id) {
      /* Print response headers for the initiated request. */
      print_header(stderr, name, namelen, value, valuelen);
      break;
    }
  }

  fprintf(stderr, "%*c} on_header_callback\n", 2 * -- Indent, ' ');
  return 0;
}

/* nghttp2_on_begin_headers_callback: Called when nghttp2 library gets
   started to receive header block. */
static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  fprintf(stderr, "%*c{ on_begin_headers_callback\n", 2 * Indent ++, ' ');
  
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE && session_data->stream_id == frame->hd.stream_id) {
      fprintf(stderr, "Response headers for stream ID=%d:\n", frame->hd.stream_id);
    }
    break;
  }

  fprintf(stderr, "%*c} on_begin_headers_callback\n", 2 * -- Indent, ' ');
  return 0;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
  
  fprintf(stderr, "%*c{ on_frame_recv_callback\n", 2 * Indent ++, ' ');

  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE && session_data->stream_id == frame->hd.stream_id) {
      fprintf(stderr, "All headers received\n");
    }
    break;
  }

  fprintf(stderr, "%*c} on_frame_recv_callback\n", 2 * -- Indent, ' ');
  return 0;
}

/* nghttp2_on_data_chunk_recv_callback: Called when DATA frame is
   received from the remote peer. In this implementation, if the frame
   is meant to the stream we initiated, print the received data in
   stdout, so that the user can redirect its output to the file
   easily. */
static int on_data_chunk_recv_callback(nghttp2_session *session, uint8_t flags,
                                       int32_t stream_id, const uint8_t *data,
                                       size_t len, void *user_data) {
  fprintf(stderr, "%*c{ on_data_chunk_callback\n", 2 * Indent ++, ' ');
  
  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;
  (void)flags;

  if (session_data->stream_id == stream_id) {
    log_data((unsigned char *)data, len);
  }

  fprintf(stderr, "%*c} on_data_chunk_callback\n", 2 * -- Indent, ' ');
  return 0;
}

/* nghttp2_on_stream_close_callback: Called when a stream is about to
   closed. This example program only deals with 1 HTTP request (1
   stream), if it is closed, we send GOAWAY and tear down the
   session */
static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  fprintf(stderr, "%*c{ on_stream_close_callback\n", 2 * Indent ++, ' ');
  
  http2_session_data *session_data = (http2_session_data *)user_data;
  int rv;

  if (session_data->stream_id == stream_id) {
    fprintf(stderr, "Stream %d closed with error_code=%u\n", stream_id, error_code);
    fprintf(stderr, "%*c nghttp2_session_terminate_session\n", 2 * Indent, ' ');        
    rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
    if (rv != 0) {
      fprintf(stderr, "%*c} on_stream_close_callback\n", 2 * -- Indent, ' ');
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  fprintf(stderr, "%*c} on_stream_close_callback2\n", 2 * -- Indent, ' ');
  return 0;
}

static int initialize_nghttp2_session(http2_session_data *psession, unsigned char *settings, int slen) {
  fprintf(stderr, "%*c{ initialize_nghttp2_session\n", 2 * Indent ++, ' ');

  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, on_begin_headers_callback);

  fprintf(stderr, "%*c nghttp2_session_client_new\n", 2 * Indent, ' ');
  int rc = nghttp2_session_client_new(&psession->session, callbacks, psession);
  if (rc != 0) {
    fprintf(stderr, "%*c} initialize_nghttp2_session\n", 2 * -- Indent, ' ');
    return -1;
  }
  nghttp2_session_callbacks_del(callbacks);

  fprintf(stderr, "%*c nghttp2_session_upgrade2\n", 2 * Indent, ' ');
  rc = nghttp2_session_upgrade2(psession->session, settings, slen, 0, NULL);
  if (rc != 0) {
    fprintf(stderr, "%*c} initialize_nghttp2_session2\n", 2 * -- Indent, ' ');
    return -1;
  }

  fprintf(stderr, "%*c} initialize_nghttp2_session3\n", 2 * -- Indent, ' ');
  return 0;
}

static int session_send(http2_session_data *psession, int sock) {
  fprintf(stderr, "%*c} session_send\n", 2 * -- Indent, ' ');

  const uint8_t *sndbuf;
  int len;

  while(1) {
    len = nghttp2_session_mem_send(psession->session, &sndbuf);
    if (len == 0)
      break;
    if (len < 0) {
      printf("nghttp2_session_mem_send returns error(%s)", nghttp2_strerror(len));
      return -1;
    }
    log_data((unsigned char *)sndbuf, len);
    len = write(sock, sndbuf, len);
    printf("writen(%d)\n", len);
  }

  fprintf(stderr, "%*c} session_send\n", 2 * -- Indent, ' ');
  return 0;
}


int main(int argc, char *argv[])
{
  fprintf(stderr, "{ main\n"); Indent ++;

  if (argc < 2) {
    printf("Usage: %s uri\n", argv[0]);
    return 1;
  }

  int rc;
  struct http_parser_url u;
  char *uri = argv[1];

  /* Parse the |uri| and stores its components in |u| */
  rc = http_parser_parse_url(uri, strlen(uri), 0, &u);
  if (rc != 0) {
    printf("Could not parse URI %s\n", uri);
    return -1;
  }

  char *host = strndup(&uri[u.field_data[UF_HOST].off], u.field_data[UF_HOST].len);
  int port;
  if (!(u.field_set & (1 << UF_PORT))) {
    port = 80;  // 443 (secure HTTP)
  } else {
    port = u.port;
  }
  char *path = strndup(&uri[u.field_data[UF_PATH].off], u.field_data[UF_PATH].len);

  int sock = connect_to(host, port);
  if (sock < 0) {
    printf("Could not connect to %s:%d\n", host, port);
    return -1;
  }

  nghttp2_settings_entry iv[] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
      {NGHTTP2_SETTINGS_ENABLE_PUSH, 0} };
  unsigned char settings[128];
  int len = nghttp2_pack_settings_payload(settings, sizeof(settings), iv, sizeof(iv) / sizeof(*iv));
  if (len <= 0) {
    printf("Could not pack SETTINGS: %s\n", nghttp2_strerror(len));
    return -1;
  }

  char req[1024];
  make_upgrade_request(req, settings, len, host, port, path);
  log_data((unsigned char *)req, strlen(req));
  rc = write(sock, req, strlen(req));
  printf("writen(%d)\n", rc);

  char rcvbuf[1024] = {0};
  rc = read(sock, (unsigned char *)rcvbuf, sizeof(rcvbuf));
  printf("read(%d)\n", rc);

  http2_session_data h2session;
  h2session.sock = sock;
  h2session.stream_id = 1;
  initialize_nghttp2_session(&h2session, settings, len);

  session_send(&h2session, sock);
  
  len = read(sock, (unsigned char *)rcvbuf, sizeof(rcvbuf));
  printf("read(%d)\n", len);
  fprintf(stderr, "%*c{ nghttp2_session_mem_recv()\n", 2 * Indent ++, ' ');
  len = nghttp2_session_mem_recv(h2session.session, (uint8_t *)rcvbuf, len);
  fprintf(stderr, "%*c} nghttp2_session_mem_recv()\n", 2 * -- Indent, ' ');
  if (len < 0) {
    printf("Recevied negative error : %s", nghttp2_strerror(len));
    return -1;
  }

  /*
  static unsigned char buf3[] = {
    0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00
  };
  rc = write(sock, buf3, sizeof(buf3));
  printf("writen(%d)\n", rc);
  */

  session_send(&h2session, sock);

  int i;
  for (i = 0; i < 4; i ++) {
    rc = read(sock, (unsigned char *)rcvbuf, sizeof(rcvbuf));
    printf("read(%d)\n", rc);
  }

  -- Indent; fprintf(stderr, "} main\n");
  return 0;
}
