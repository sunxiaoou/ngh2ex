#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif /* HAVE_SYS_SOCKET_H */
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif /* HAVE_NETDB_H */
#include <signal.h>
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif /* HAVE_UNISTD_H */
#include <sys/stat.h>
#ifdef HAVE_FCNTL_H
#  include <fcntl.h>
#endif /* HAVE_FCNTL_H */
#include <ctype.h>
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif /* HAVE_NETINET_IN_H */
#include <netinet/tcp.h>
#ifndef __sgi
#  include <err.h>
#endif
#include <string.h>
#include <errno.h>

#include <event.h>
#include <event2/event.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>

#include <nghttp2/nghttp2.h>

#define OUTPUT_WOULDBLOCK_THRESHOLD (1 << 16)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

struct app_context;
typedef struct app_context app_context;

typedef struct http2_stream_data {
  struct http2_stream_data *prev, *next;
  char *request_path;
  int32_t stream_id;
  int fd;
} http2_stream_data;

typedef struct http2_session_data {
  struct http2_stream_data root;
  struct bufferevent *bev;
  app_context *app_ctx;
  nghttp2_session *session;
  char *client_addr;
} http2_session_data;

struct app_context {
  // SSL_CTX *ssl_ctx;
  struct event_base *evbase;
};

static unsigned char next_proto_list[256];
static size_t next_proto_list_len;

static int Indent = 0;

static void log_data(unsigned char *data, int len)
{
	unsigned char c;
	char tmbuf[40];
	int i, j, maxlen;

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

static void add_stream(http2_session_data *session_data,
                       http2_stream_data *stream_data) {
  fprintf(stderr, "%*c{ add_stream\n", 2 * Indent ++, ' ');                         
                           
  stream_data->next = session_data->root.next;
  session_data->root.next = stream_data;
  stream_data->prev = &session_data->root;
  if (stream_data->next) {
    stream_data->next->prev = stream_data;
  }

  fprintf(stderr, "%*c} add_stream\n", 2 * -- Indent, ' ');
}

static void remove_stream(http2_session_data *session_data,
                          http2_stream_data *stream_data) {
  fprintf(stderr, "%*c{ remove_stream\n", 2 * Indent ++, ' ');
  
  (void)session_data;

  stream_data->prev->next = stream_data->next;
  if (stream_data->next) {
    stream_data->next->prev = stream_data->prev;
  }

  fprintf(stderr, "%*c} remove_stream\n", 2 * -- Indent, ' ');
}

static http2_stream_data *
create_http2_stream_data(http2_session_data *session_data, int32_t stream_id) {
  fprintf(stderr, "%*c{ create_http2_stream_data\n", 2 * Indent ++, ' ');
  
  http2_stream_data *stream_data;
  stream_data = malloc(sizeof(http2_stream_data));
  memset(stream_data, 0, sizeof(http2_stream_data));
  stream_data->stream_id = stream_id;
  stream_data->fd = -1;

  add_stream(session_data, stream_data);

  fprintf(stderr, "%*c} create_http2_stream_data\n", 2 * -- Indent, ' ');
  return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
  fprintf(stderr, "%*c{ delete_http2_stream_data\n", 2 * Indent ++, ' ');

  if (stream_data->fd != -1) {
    close(stream_data->fd);
  }
  free(stream_data->request_path);
  free(stream_data);

  fprintf(stderr, "%*c} delete_http2_stream_data\n", 2 * -- Indent, ' ');
}

static http2_session_data *create_http2_session_data(app_context *app_ctx,
                                                     int fd,
                                                     struct sockaddr *addr,
                                                     int addrlen) {
  fprintf(stderr, "%*c{ create_http2_session_data\n", 2 * Indent ++, ' ');
  
  int rv;
  http2_session_data *session_data;
  char host[NI_MAXHOST];
  int val = 1;

  session_data = malloc(sizeof(http2_session_data));
  memset(session_data, 0, sizeof(http2_session_data));
  session_data->app_ctx = app_ctx;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(val));
  session_data->bev = bufferevent_socket_new(
      app_ctx->evbase, fd, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);
  bufferevent_enable(session_data->bev, EV_READ | EV_WRITE);
  rv = getnameinfo(addr, (socklen_t)addrlen, host, sizeof(host), NULL, 0,
                   NI_NUMERICHOST);
  if (rv != 0) {
    session_data->client_addr = strdup("(unknown)");
  } else {
    session_data->client_addr = strdup(host);
  }

  fprintf(stderr, "%*c} create_http2_session_data\n", 2 * -- Indent, ' ');
  return session_data;
}

static void delete_http2_session_data(http2_session_data *session_data) {
  fprintf(stderr, "%*c{ delete_http2_session_data\n", 2 * Indent ++, ' ');
  
  http2_stream_data *stream_data;
  bufferevent_free(session_data->bev);

  fprintf(stderr, "%*c nghttp2_session_del\n", 2 * Indent, ' ');
  nghttp2_session_del(session_data->session);
  for (stream_data = session_data->root.next; stream_data;) {
    http2_stream_data *next = stream_data->next;
    delete_http2_stream_data(stream_data);
    stream_data = next;
  }
  free(session_data->client_addr);
  free(session_data);

  fprintf(stderr, "%*c} delete_http2_session_data\n", 2 * -- Indent, ' ');
}

/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int session_send(http2_session_data *session_data) {
  fprintf(stderr, "%*c{ session_send\n", 2 * Indent ++, ' ');
  
  int rv;

  fprintf(stderr, "%*c nghttp2_session_send\n", 2 * Indent, ' ');
  rv = nghttp2_session_send(session_data->session);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    fprintf(stderr, "%*c} session_send\n", 2 * -- Indent, ' ');
    return -1;
  }

  fprintf(stderr, "%*c} session_send2\n", 2 * -- Indent, ' ');
  return 0;
}

/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int session_recv(http2_session_data *session_data) {
  fprintf(stderr, "%*c{ session_recv\n", 2 * Indent ++, ' ');
  
  ssize_t readlen;
  struct evbuffer *input = bufferevent_get_input(session_data->bev);
  size_t datalen = evbuffer_get_length(input);
  unsigned char *data = evbuffer_pullup(input, -1);

  log_data(data, datalen);
  fprintf(stderr, "%*c{ nghttp2_session_mem_recv\n", 2 * Indent ++, ' ');
  readlen = nghttp2_session_mem_recv(session_data->session, data, datalen);
  fprintf(stderr, "%*c} nghttp2_session_mem_recv\n", 2 * -- Indent, ' ');
  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    fprintf(stderr, "%*c} session_recv\n", 2 * -- Indent, ' ');
    return -1;
  }
  if (evbuffer_drain(input, (size_t)readlen) != 0) {
    warnx("Fatal error: evbuffer_drain failed");
    fprintf(stderr, "%*c} session_recv2\n", 2 * -- Indent, ' ');
    return -1;
  }
  if (session_send(session_data) != 0) {
    fprintf(stderr, "%*c} session_recv3\n", 2 * -- Indent, ' ');
    return -1;
  }

  fprintf(stderr, "%*c} session_recv4\n", 2 * -- Indent, ' ');
  return 0;
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data) {
  fprintf(stderr, "%*c{ send_callback\n", 2 * Indent ++, ' ');
  
  http2_session_data *session_data = (http2_session_data *)user_data;
  struct bufferevent *bev = session_data->bev;
  (void)session;
  (void)flags;

  /* Avoid excessive buffering in server side. */
  if (evbuffer_get_length(bufferevent_get_output(session_data->bev)) >=
      OUTPUT_WOULDBLOCK_THRESHOLD) {

    fprintf(stderr, "%*c} send_callback\n", 2 * -- Indent, ' ');    
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  log_data((unsigned char *)data, length);
  bufferevent_write(bev, data, length);

  fprintf(stderr, "%*c} send_callback2\n", 2 * -- Indent, ' ');
  return (ssize_t)length;
}

/* Returns nonzero if the string |s| ends with the substring |sub| */
static int ends_with(const char *s, const char *sub) {
  size_t slen = strlen(s);
  size_t sublen = strlen(sub);
  if (slen < sublen) {
    return 0;
  }
  return memcmp(s + slen - sublen, sub, sublen) == 0;
}

/* Returns int value of hex string character |c| */
static uint8_t hex_to_uint(uint8_t c) {
  if ('0' <= c && c <= '9') {
    return (uint8_t)(c - '0');
  }
  if ('A' <= c && c <= 'F') {
    return (uint8_t)(c - 'A' + 10);
  }
  if ('a' <= c && c <= 'f') {
    return (uint8_t)(c - 'a' + 10);
  }
  return 0;
}

/* Decodes percent-encoded byte string |value| with length |valuelen|
   and returns the decoded byte string in allocated buffer. The return
   value is NULL terminated. The caller must free the returned
   string. */
static char *percent_decode(const uint8_t *value, size_t valuelen) {
  char *res;

  res = malloc(valuelen + 1);
  if (valuelen > 3) {
    size_t i, j;
    for (i = 0, j = 0; i < valuelen - 2;) {
      if (value[i] != '%' || !isxdigit(value[i + 1]) ||
          !isxdigit(value[i + 2])) {
        res[j++] = (char)value[i++];
        continue;
      }
      res[j++] =
          (char)((hex_to_uint(value[i + 1]) << 4) + hex_to_uint(value[i + 2]));
      i += 3;
    }
    memcpy(&res[j], &value[i], 2);
    res[j + 2] = '\0';
  } else {
    memcpy(res, value, valuelen);
    res[valuelen] = '\0';
  }
  return res;
}

static ssize_t file_read_callback(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data) {
  fprintf(stderr, "%*c{ file_read_callback\n", 2 * Indent ++, ' ');
  
  int fd = source->fd;
  ssize_t r;
  (void)session;
  (void)stream_id;
  (void)user_data;

  while ((r = read(fd, buf, length)) == -1 && errno == EINTR)
    ;
  if (r == -1) {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  if (r == 0) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }

  fprintf(stderr, "%*c} file_read_callback\n", 2 * -- Indent, ' ');
  return r;
}

static int send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, int fd) {
  fprintf(stderr, "%*c{ send_response\n", 2 * Indent ++, ' ');

  int rv;
  nghttp2_data_provider data_prd;
  data_prd.source.fd = fd;
  data_prd.read_callback = file_read_callback;

  fprintf(stderr, "%*c nghttp2_submit_response\n", 2 * Indent, ' ');  
  rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));

    fprintf(stderr, "%*c} send_response\n", 2 * -- Indent, ' ');
    return -1;
  }

  fprintf(stderr, "%*c} send_response2\n", 2 * -- Indent, ' ');
  return 0;
}

static const char ERROR_HTML[] = "<html><head><title>404</title></head>"
                                 "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session,
                       http2_stream_data *stream_data) {
  fprintf(stderr, "%*c{ error_reply\n", 2 * Indent ++, ' ');

  int rv;
  ssize_t writelen;
  int pipefd[2];
  nghttp2_nv hdrs[] = {MAKE_NV(":status", "404")};

  rv = pipe(pipefd);
  if (rv != 0) {
    warn("Could not create pipe");
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                   stream_data->stream_id,
                                   NGHTTP2_INTERNAL_ERROR);
    if (rv != 0) {
      warnx("Fatal error: %s", nghttp2_strerror(rv));
      fprintf(stderr, "%*c} error_reply\n", 2 * -- Indent, ' ');
      return -1;
    }
    
    fprintf(stderr, "%*c} error_reply2\n", 2 * -- Indent, ' ');
    return 0;
  }

  writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
  close(pipefd[1]);

  if (writelen != sizeof(ERROR_HTML) - 1) {
    close(pipefd[0]);

    fprintf(stderr, "%*c} error_reply3\n", 2 * -- Indent, ' ');
    return -1;
  }

  stream_data->fd = pipefd[0];

  if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs),
                    pipefd[0]) != 0) {
    close(pipefd[0]);

    fprintf(stderr, "%*c} error_reply4\n", 2 * -- Indent, ' ');
    return -1;
  }

  fprintf(stderr, "%*c} error_reply5\n", 2 * -- Indent, ' ');
  return 0;
}

/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  fprintf(stderr, "%*c{ on_header_callback\n", 2 * Indent ++, ' ');
  
  http2_stream_data *stream_data;
  const char PATH[] = ":path";
  (void)flags;
  (void)user_data;

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }

    fprintf(stderr, "%*c nghttp2_session_get_stream_user_data\n", 2 * Indent, ' '); 
    stream_data =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
    if (!stream_data || stream_data->request_path) {
      break;
    }
    if (namelen == sizeof(PATH) - 1 && memcmp(PATH, name, namelen) == 0) {
      size_t j;
      for (j = 0; j < valuelen && value[j] != '?'; ++j)
        ;
      stream_data->request_path = percent_decode(value, j);
    }
    break;
  }

  fprintf(stderr, "%*c} on_header_callback\n", 2 * -- Indent, ' ');
  return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  fprintf(stderr, "%*c{ on_begin_headers_callback\n", 2 * Indent ++, ' ');

  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    fprintf(stderr, "%*c} on_begin_headers_callback\n", 2 * -- Indent, ' ');    
    return 0;
  }
  stream_data = create_http2_stream_data(session_data, frame->hd.stream_id);
  
  fprintf(stderr, "%*c nghttp2_session_set_stream_user_data\n", 2 * Indent, ' '); 
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                       stream_data);
  
  fprintf(stderr, "%*c} on_begin_headers_callback2\n", 2 * -- Indent, ' ');    
  return 0;
}

/* Minimum check for directory traversal. Returns nonzero if it is
   safe. */
static int check_path(const char *path) {
  /* We don't like '\' in url. */
  fprintf(stderr, "%*c{ check_path\n", 2 * Indent ++, ' ');
  fprintf(stderr, "%*c} check_path\n", 2 * -- Indent, ' ');
  return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
         strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
         !ends_with(path, "/..") && !ends_with(path, "/.");
}

static int on_request_recv(nghttp2_session *session,
                           http2_session_data *session_data,
                           http2_stream_data *stream_data) {
  fprintf(stderr, "%*c{ on_request_recv\n", 2 * Indent ++, ' ');
  
  int fd;
  nghttp2_nv hdrs[] = {MAKE_NV(":status", "200")};
  char *rel_path;

  if (!stream_data->request_path) {
    if (error_reply(session, stream_data) != 0) {
      fprintf(stderr, "%*c} on_request_recv1\n", 2 * -- Indent, ' ');
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    fprintf(stderr, "%*c} on_request_recv2\n", 2 * -- Indent, ' ');
    return 0;
  }
  fprintf(stderr, "%s GET %s\n", session_data->client_addr,
          stream_data->request_path);
  if (!check_path(stream_data->request_path)) {
    if (error_reply(session, stream_data) != 0) {
      fprintf(stderr, "%*c} on_request_recv3\n", 2 * -- Indent, ' ');
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    
    fprintf(stderr, "%*c} on_request_recv4\n", 2 * -- Indent, ' ');
    return 0;
  }
  for (rel_path = stream_data->request_path; *rel_path == '/'; ++rel_path)
    ;
  fd = open(rel_path, O_RDONLY);
  if (fd == -1) {
    if (error_reply(session, stream_data) != 0) {
      fprintf(stderr, "%*c} on_request_recv5\n", 2 * -- Indent, ' ');
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    fprintf(stderr, "%*c} on_request_recv6\n", 2 * -- Indent, ' ');
    return 0;
  }
  stream_data->fd = fd;

  if (send_response(session, stream_data->stream_id, hdrs, ARRLEN(hdrs), fd) !=
      0) {
    close(fd);
    fprintf(stderr, "%*c} on_request_recv7\n", 2 * -- Indent, ' ');
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  fprintf(stderr, "%*c} on_request_recv8\n", 2 * -- Indent, ' ');
  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  fprintf(stderr, "%*c{ on_frame_recv_callback\n", 2 * Indent ++, ' ');
  
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  switch (frame->hd.type) {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS:
    /* Check that the client request has finished */
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      fprintf(stderr, "%*c nghttp2_session_get_stream_user_data\n", 2 * Indent, ' ');
      stream_data =
          nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
      if (!stream_data) {
        fprintf(stderr, "%*c} on_frame_recv_callback\n", 2 * -- Indent, ' ');
        return 0;
      }
      fprintf(stderr, "%*c} on_frame_recv_callback2\n", 2 * -- Indent, ' ');
      return on_request_recv(session, session_data, stream_data);
    }
    break;
  default:
    break;
  }

  fprintf(stderr, "%*c} on_frame_recv_callback3\n", 2 * -- Indent, ' ');
  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  fprintf(stderr, "%*c{ on_stream_close_callback\n", 2 * Indent ++, ' ');
  
  http2_session_data *session_data = (http2_session_data *)user_data;
  http2_stream_data *stream_data;
  (void)error_code;

  fprintf(stderr, "%*c nghttp2_session_get_stream_user_data\n", 2 * Indent, ' ');
  stream_data = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!stream_data) {
    fprintf(stderr, "%*c} on_stream_close_callback\n", 2 * -- Indent, ' ');
    return 0;
  }
  remove_stream(session_data, stream_data);
  delete_http2_stream_data(stream_data);

  fprintf(stderr, "%*c} on_stream_close_callback2\n", 2 * -- Indent, ' ');
  return 0;
}

static void initialize_nghttp2_session(http2_session_data *session_data) {
  fprintf(stderr, "%*c{ initialize_nghttp2_session\n", 2 * Indent ++, ' ');

  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);

  nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback(callbacks,
                                                   on_header_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback(
      callbacks, on_begin_headers_callback);

  fprintf(stderr, "%*c nghttp2_session_server_new\n", 2 * Indent, ' ');
  nghttp2_session_server_new(&session_data->session, callbacks, session_data);

  nghttp2_session_callbacks_del(callbacks);

  fprintf(stderr, "%*c} initialize_nghttp2_session\n", 2 * -- Indent, ' ');
}

/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int send_server_connection_header(http2_session_data *session_data) {
  fprintf(stderr, "%*c{ send_server_connection_header\n", 2 * Indent ++, ' ');
  nghttp2_settings_entry iv[1] = {
      {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};
  int rv;

  fprintf(stderr, "%*c nghttp2_submit_settings\n", 2 * Indent, ' ');
  rv = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv,
                               ARRLEN(iv));
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  fprintf(stderr, "%*c} send_server_connection_header\n", 2 * -- Indent, ' ');
  return 0;
}

/* readcb for bufferevent after client connection header was
   checked. */
static void readcb(struct bufferevent *bev, void *ptr) {
  fprintf(stderr, "%*c{ readcb\n", 2 * Indent ++, ' ');
  http2_session_data *session_data = (http2_session_data *)ptr;
  (void)bev;

  if (session_recv(session_data) != 0) {
    delete_http2_session_data(session_data);
    fprintf(stderr, "%*c} readcb\n", 2 * -- Indent, ' ');
    return;
  }
  fprintf(stderr, "%*c} readcb2\n", 2 * -- Indent, ' ');
}

/* writecb for bufferevent. To greaceful shutdown after sending or
   receiving GOAWAY, we check the some conditions on the nghttp2
   library and output buffer of bufferevent. If it indicates we have
   no business to this session, tear down the connection. If the
   connection is not going to shutdown, we call session_send() to
   process pending data in the output buffer. This is necessary
   because we have a threshold on the buffer size to avoid too much
   buffering. See send_callback(). */
static void writecb(struct bufferevent *bev, void *ptr) {
  fprintf(stderr, "%*c{ writecb\n", 2 * Indent ++, ' ');
  http2_session_data *session_data = (http2_session_data *)ptr;
  if (evbuffer_get_length(bufferevent_get_output(bev)) > 0) {
    fprintf(stderr, "%*c} writecb\n", 2 * -- Indent, ' ');
    return;
  }
  if (nghttp2_session_want_read(session_data->session) == 0 &&
      nghttp2_session_want_write(session_data->session) == 0) {
    delete_http2_session_data(session_data);
    fprintf(stderr, "%*c} writecb2\n", 2 * -- Indent, ' ');
    return;
  }
  if (session_send(session_data) != 0) {
    delete_http2_session_data(session_data);
    fprintf(stderr, "%*c} writecb3\n", 2 * -- Indent, ' ');
    return;
  }
  fprintf(stderr, "%*c} writecb4\n", 2 * -- Indent, ' ');
}

/* eventcb for bufferevent */
static void eventcb(struct bufferevent *bev, short events, void *ptr) {
  fprintf(stderr, "%*c{ eventcb\n", 2 * Indent ++, ' ');
  http2_session_data *session_data = (http2_session_data *)ptr;
  if (events & BEV_EVENT_EOF) {
    fprintf(stderr, "%s EOF\n", session_data->client_addr);
  } else if (events & BEV_EVENT_ERROR) {
    fprintf(stderr, "%s network error\n", session_data->client_addr);
  } else if (events & BEV_EVENT_TIMEOUT) {
    fprintf(stderr, "%s timeout\n", session_data->client_addr);
  }
  delete_http2_session_data(session_data);
  fprintf(stderr, "%*c} eventcb4\n", 2 * -- Indent, ' ');
}

/* callback for evconnlistener */
static void acceptcb(struct evconnlistener *listener, int fd,
                     struct sockaddr *addr, int addrlen, void *arg) {
  fprintf(stderr, "%*c{ acceptcb\n", 2 * Indent ++, ' ');                     
  app_context *app_ctx = (app_context *)arg;
  http2_session_data *session_data;
  (void)listener;

  session_data = create_http2_session_data(app_ctx, fd, addr, addrlen);

  bufferevent_setcb(session_data->bev, readcb, writecb, eventcb, session_data);

    fprintf(stderr, "%s connected\n", session_data->client_addr);

    initialize_nghttp2_session(session_data);

    if (send_server_connection_header(session_data) != 0 ||
        session_send(session_data) != 0) {
      delete_http2_session_data(session_data);
      fprintf(stderr, "%*c} eventcb2\n", 2 * -- Indent, ' ');
      return;
    }


  fprintf(stderr, "%*c} acceptcb\n", 2 * -- Indent, ' ');
}

static void start_listen(struct event_base *evbase, const char *service,
                         app_context *app_ctx) {
  fprintf(stderr, "%*c{ start_listen\n", 2 * Indent ++, ' ');                         
  int rv;
  struct addrinfo hints;
  struct addrinfo *res, *rp;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
#ifdef AI_ADDRCONFIG
  hints.ai_flags |= AI_ADDRCONFIG;
#endif /* AI_ADDRCONFIG */

  rv = getaddrinfo(NULL, service, &hints, &res);
  if (rv != 0) {
    errx(1, "Could not resolve server address");
  }
  for (rp = res; rp; rp = rp->ai_next) {
    struct evconnlistener *listener;
    listener = evconnlistener_new_bind(
        evbase, acceptcb, app_ctx, LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE,
        16, rp->ai_addr, (int)rp->ai_addrlen);
    if (listener) {
      freeaddrinfo(res);

      fprintf(stderr, "%*c} start_listen\n", 2 * -- Indent, ' ');                         
      return;
    }
  }
  errx(1, "Could not start listener");
}

static void initialize_app_context(app_context *app_ctx, struct event_base *evbase) {
  fprintf(stderr, "%*c{ initialize_app_context\n", 2 * Indent ++, ' ');
  memset(app_ctx, 0, sizeof(app_context));
  app_ctx->evbase = evbase;
  fprintf(stderr, "%*c} initialize_app_context\n", 2 * -- Indent, ' ');
}

static void run(const char *service) {
  fprintf(stderr, "%*c{ Run\n", 2 * Indent ++, ' ');
  app_context app_ctx;
  struct event_base *evbase;

  evbase = event_base_new();
  initialize_app_context(&app_ctx, evbase);
  start_listen(evbase, service, &app_ctx);

  event_base_loop(evbase, 0);

  event_base_free(evbase);
  fprintf(stderr, "%*c} Run\n", 2 * -- Indent, ' ');
}

int main(int argc, char **argv) {
  struct sigaction act;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s PORT\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &act, NULL);

  run(argv[1]);
  return 0;
}
