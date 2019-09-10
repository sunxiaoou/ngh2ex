// A sample of a nghttp2 client without security
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
  unsigned int upgrade_response_status;
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
  fprintf(stderr, "%*c{ connect_to\n", 2 * Indent ++, ' ');

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
    fprintf(stderr, "%*c} connect_to\n", 2 * -- Indent, ' ');
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

  fprintf(stderr, "%*c} connect_to2\n", 2 * -- Indent, ' ');
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

static int parser_completecb(http_parser *parser) {
  fprintf(stderr, "%*c{ parser_completecb\n", 2 * Indent ++, ' ');

  http2_session_data *session_data = (http2_session_data *)parser->data;
  session_data->upgrade_response_status = parser->status_code;

  fprintf(stderr, "%*c} parser_completecb\n", 2 * -- Indent, ' ');
  return 0;
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

static char *strframetype(uint8_t type) {
  switch (type) {
  case NGHTTP2_DATA:
    return "DATA";
  case NGHTTP2_HEADERS:
    return "HEADERS";
  case NGHTTP2_PRIORITY:
    return "PRIORITY";
  case NGHTTP2_RST_STREAM:
    return "RST_STREAM";
  case NGHTTP2_SETTINGS:
    return "SETTINGS";
  case NGHTTP2_PUSH_PROMISE:
    return "PUSH_PROMISE";
  case NGHTTP2_PING:
    return "PING";
  case NGHTTP2_GOAWAY:
    return "GOAWAY";
  case NGHTTP2_WINDOW_UPDATE:
    return "WINDOW_UPDATE";
  case NGHTTP2_ALTSVC:
    return "ALTSVC";
  case NGHTTP2_ORIGIN:
    return "ORIGIN";
  default:
    return "UNKNOWN";
  }
}

static char *strsettingsid(int id) {
  switch (id) {
  case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
    return "SETTINGS_HEADER_TABLE_SIZE";
  case NGHTTP2_SETTINGS_ENABLE_PUSH:
    return "SETTINGS_ENABLE_PUSH";
  case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
    return "SETTINGS_MAX_CONCURRENT_STREAMS";
  case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
    return "SETTINGS_INITIAL_WINDOW_SIZE";
  case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
    return "SETTINGS_MAX_FRAME_SIZE";
  case NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
    return "SETTINGS_MAX_HEADER_LIST_SIZE";
  case NGHTTP2_SETTINGS_ENABLE_CONNECT_PROTOCOL:
    return "SETTINGS_ENABLE_CONNECT_PROTOCOL";
  default:
    return "UNKNOWN";
  }
}

#define APPEND(S, S2) { \
  strcpy(S, S2); S += strlen(S2); \
}

static char *strflags(const nghttp2_frame_hd *hd) {
  char str[100];
  memset(str, 0, sizeof(str));
  char *s = str;

  switch (hd->type) {
  case NGHTTP2_DATA:
    if (hd->flags & NGHTTP2_FLAG_END_STREAM) {
      APPEND(s, "END_STREAM")
    }
    if (hd->flags & NGHTTP2_FLAG_PADDED) {
      if (! *s) {
        APPEND(s, " | ")
      }
      APPEND(s, "PADDED")
    }
    break;
  case NGHTTP2_HEADERS:
    if (hd->flags & NGHTTP2_FLAG_END_STREAM) {
      APPEND(s, "END_STREAM")
    }
    if (hd->flags & NGHTTP2_FLAG_END_HEADERS) {
      if (s != str) {
        APPEND(s, " | ")
      }
      APPEND(s, "END_HEADERS")
    }
    if (hd->flags & NGHTTP2_FLAG_PADDED) {
      if (s != str) {
        APPEND(s, " | ")
      }
      APPEND(s, "PADDED")
    }
    if (hd->flags & NGHTTP2_FLAG_PRIORITY) {
      if (s != str) {
        APPEND(s, " | ")
      }
      APPEND(s, "PRIORITY")
    }
    break;
  case NGHTTP2_PRIORITY:
    break;
  case NGHTTP2_SETTINGS:
    if (hd->flags & NGHTTP2_FLAG_ACK) {
      return "ACK";
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    if (hd->flags & NGHTTP2_FLAG_END_HEADERS) {
      APPEND(s, "END_HEADERS")
    }
    if (hd->flags & NGHTTP2_FLAG_PADDED) {
      if (! *s) {
        APPEND(s, " | ")
      }
      APPEND(s, "PADDED")
    }
    break;
  case NGHTTP2_PING:
    if (hd->flags & NGHTTP2_FLAG_ACK) {
      return "ACK";
    }
    break;
  }

  return s = str;
}

/* nghttp2_on_frame_recv_callback: Called when nghttp2 library
   received a complete frame from the remote peer. */
static int on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {

  fprintf(stderr, "%*c{ on_frame_recv_callback\n", 2 * Indent ++, ' ');

  http2_session_data *session_data = (http2_session_data *)user_data;
  (void)session;

  fprintf(stderr, "%s frame <length=%zu, flags=%s, stream_id=%d>\n",
      strframetype(frame->hd.type), frame->hd.length, strflags(&frame->hd), frame->hd.stream_id);

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE && session_data->stream_id == frame->hd.stream_id) {
      fprintf(stderr, "All headers received\n");
    }
    break;
  case NGHTTP2_SETTINGS:
    fprintf(stderr, "(niv=%u)\n", (int)frame->settings.niv);
    for (int i = 0; i < frame->settings.niv; ++ i) {
      fprintf(stderr, "[%s(0x%02x):%u]\n", strsettingsid(frame->settings.iv[i].settings_id),
          frame->settings.iv[i].settings_id, frame->settings.iv[i].value);
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
  fprintf(stderr, "%*c{ session_send\n", 2 * Indent ++, ' ');

  const uint8_t *sndbuf;
  int len;

  while(1) {
    len = nghttp2_session_mem_send(psession->session, &sndbuf);
    if (len == 0)
      break;
    if (len < 0) {
      fprintf(stderr, "nghttp2_session_mem_send returns error(%s)", nghttp2_strerror(len));
      return -1;
    }
    log_data((unsigned char *)sndbuf, len);
    len = write(sock, sndbuf, len);
    fprintf(stderr, "writen(%d)\n", len);
  }

  if (nghttp2_session_want_read(psession->session) == 0 &&
      nghttp2_session_want_write(psession->session) == 0) {
    fprintf(stderr, "%*c} session_send\n", 2 * -- Indent, ' ');
    return -1;
  }

  fprintf(stderr, "%*c} session_send\n", 2 * -- Indent, ' ');
  return 0;
}

static int session_receive(http2_session_data *psession, int sock) {
  fprintf(stderr, "%*c{ session_receive\n", 2 * Indent ++, ' ');

  unsigned char rcvbuf[1024];

  int len = read(sock, rcvbuf, sizeof(rcvbuf));
  if (len > 20 && rcvbuf[16] == 2 && rcvbuf[20] == 1) // workaround for Bug 30267014
    rcvbuf[20] = 0;
  log_data(rcvbuf, len);
  fprintf(stderr, "%*c{ nghttp2_session_mem_recv()\n", 2 * Indent ++, ' ');
  len = nghttp2_session_mem_recv(psession->session, (uint8_t *)rcvbuf, len);
  fprintf(stderr, "%*c} nghttp2_session_mem_recv()\n", 2 * -- Indent, ' ');
  if (len < 0) {
    fprintf(stderr, "Recevied negative error : %s", nghttp2_strerror(len));
    return -1;
  }

  fprintf(stderr, "%*c} session_receive\n", 2 * -- Indent, ' ');
  return 0;
}

int main(int argc, char *argv[])
{
  fprintf(stderr, "{ main\n"); Indent ++;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s uri\n", argv[0]);
    return 1;
  }

  int rc;
  struct http_parser_url u;
  char *uri = argv[1];

  /* Parse the |uri| and stores its components in |u| */
  rc = http_parser_parse_url(uri, strlen(uri), 0, &u);
  if (rc != 0) {
    fprintf(stderr, "Could not parse URI %s\n", uri);
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
    fprintf(stderr, "Could not connect to %s:%d\n", host, port);
    return -1;
  }

  nghttp2_settings_entry iv[] = {
    {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100},
    {NGHTTP2_SETTINGS_ENABLE_PUSH, 0}
  };
  unsigned char settings[128];
  int len = nghttp2_pack_settings_payload(settings, sizeof(settings), iv, sizeof(iv) / sizeof(*iv));
  if (len <= 0) {
    fprintf(stderr, "Could not pack SETTINGS: %s\n", nghttp2_strerror(len));
    return -1;
  }

  /* send upgrade request */
  char req[1024];
  make_upgrade_request(req, settings, len, host, port, path);
  log_data((unsigned char *)req, strlen(req));
  rc = write(sock, req, strlen(req));
  fprintf(stderr, "writen(%d)\n", rc);

  /* receive 101 switching protocols */
  char rcvbuf[1024] = {0};
  rc = read(sock, rcvbuf, sizeof(rcvbuf));
  fprintf(stderr, "read(%d)\n", rc);

  http_parser_settings parser_settings = {
    NULL,              // http_cb      on_message_begin;
    NULL,              // http_data_cb on_url;
    NULL,              // http_data_cb on_status;
    NULL,              // http_data_cb on_header_field;
    NULL,              // http_data_cb on_header_value;
    NULL,              // http_cb      on_headers_complete;
    NULL,              // http_data_cb on_body;
    parser_completecb  // http_cb      on_message_complete;
  };
  http_parser parser;
  http_parser_init(&parser, HTTP_RESPONSE);
  http2_session_data h2session;
  parser.data = &h2session;

  rc = http_parser_execute(&parser, &parser_settings, rcvbuf, rc);
  int htperr = parser.http_errno;
  if (htperr != HPE_OK) {
    fprintf(stderr, "Failed to parse HTTP Upgrade response header %s\n:", http_errno_name(htperr));
    return -1;
  }

  if (h2session.upgrade_response_status != 101) {
    fprintf(stderr, "HTTP Upgrade failed");
    return -1;
  }

  h2session.sock = sock;
  h2session.stream_id = 1;

  /* send magic with settings */
  initialize_nghttp2_session(&h2session, settings, len);
  session_send(&h2session, sock);

  int maxfd = sock + 1;
  fd_set rset;
  FD_ZERO(&rset);
  while (1) {
    FD_SET(sock, &rset);
     select(maxfd, &rset, NULL, NULL, NULL);
     if (FD_ISSET(sock, &rset)) {
        session_receive(&h2session, sock);
        if (session_send(&h2session, sock) < 0)
          break;
     }
  }

  -- Indent; fprintf(stderr, "} main\n");
  return 0;
}
