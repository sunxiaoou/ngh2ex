// A sample of a nghttp2 server without security
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include <nghttp2/nghttp2.h>

#include "http-parser/http_parser.h"
#include "log/log.h"

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))
#define MAKE_NV(NAME, VALUE, VALUELEN)                                         \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }
#define MAKE_NV2(NAME, VALUE)                                                  \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

typedef struct http2_stream_data {
  struct http2_stream_data *prev, *next;
  char *uri;
  char *authority;
  int32_t id;
  int fd;
} http2_stream_data;

typedef struct http2_session_data {
  // char *client_addr;
  const char *push_path;
  char uri[256];
  char authority[128];
  http2_stream_data root;
  nghttp2_session *session;
} http2_session_data;

typedef struct fd_state {
    int writing;
    http2_session_data h2session;
} fd_state;

static int listen_(int port, int nlisten) {
  PRINT(log_in, "listen_")

  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (socket < 0) {
    perror("socket failed");
    PRINT(log_out, "listen_")
    return -1;
  }

  // fcntl(sock, F_SETFL, O_NONBLOCK);

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = htonl(INADDR_ANY);
  sin.sin_port = htons(port);

  int rc = bind(sock, (struct sockaddr *)(&sin), sizeof(struct sockaddr_in));
  if (rc < 0) {
    perror("bind failed");
    close(sock);
    PRINT(log_out, "listen_2")
    return -1;
  }

  rc = listen(sock, nlisten);
  if (rc < 0) {
    perror("listen failed");
    close(sock);
    PRINT(log_out, "listen_3")
    return -1;
  }

  PRINT(log_out, "listen_4")
  return sock;
}

static int accept_(int listener) {
  PRINT(log_in, "accept_")

  struct sockaddr_in sin;
  unsigned long len = sizeof(struct sockaddr_in);
  int sock = accept(listener, (struct sockaddr *)(&sin), (socklen_t *)&len);
  if (sock < 0) {
    perror("accept");
    PRINT(log_out, "accept_")
    return -1;
  }

  PRINT(log_out, "accept_2")
  return sock;
}

fd_state *alloc_fd_state(void) {
  PRINT(log_still, "alloc_fd_state")
  fd_state *state = malloc(sizeof(fd_state));
  if (! state)
    return NULL;

  memset(state, 0, sizeof(fd_state));
  return state;
}

void free_fd_state(fd_state *state) {
  PRINT(log_still, "free_fd_state")
  free(state);
}

static int htp_uricb(http_parser *htp, const char *data, size_t len) {
  PRINT(log_in, "htp_uricb")
  fprintf(stderr, "method(%d)\n", htp->method);
  fprintf(stderr, "uri(%.*s)\n", (int)len, data);
  http2_session_data *p = htp->data;
  strncpy(p->uri, data, len);
  PRINT(log_out, "htp_uricb")
  return 0;
}

static int htp_hdr_keycb(http_parser *htp, const char *data, size_t len) {
  fprintf(stderr, "hdr_key(%.*s)\n", (int)len, data);
  if (! strncmp(data, "host", len)) {
    http2_session_data *p = htp->data;
    strncpy(p->authority, data, len);
  }
  return 0;
}

static int htp_hdr_valcb(http_parser *htp, const char *data, size_t len) {
  fprintf(stderr, "hdr_val(%.*s)\n", (int)len, data);
  http2_session_data *p = htp->data;
  if (! strncmp(p->authority, "host", len)) {
    strncpy(p->authority, data, len);
  }
  return 0;
}

static int htp_hdrs_completecb(http_parser *htp) {
  PRINT(log_in, "htp_hdrs_completecb")
  fprintf(stderr, "http_major(%d), http_minor(%d)\n", htp->http_major, htp->http_minor);
  PRINT(log_out, "htp_hdrs_completecb")
  return 0;
}

static int htp_msg_completecb(http_parser *htp) {
  PRINT(log_in, "htp_msg_completecb")
  http_parser_pause(htp, 1);
  PRINT(log_out, "htp_msg_completecb")
  return 0;
}

static int parse_htp(http2_session_data *session_data, char *buffer, int buflen) {
  PRINT(log_in, "parse_htp")

  http_parser_settings parser_settings = {
    NULL,                // http_cb      on_message_begin;
    htp_uricb,           // http_data_cb on_url;
    NULL,                // http_data_cb on_status;
    htp_hdr_keycb,       // http_data_cb on_header_field;
    htp_hdr_valcb,       // http_data_cb on_header_value;
    htp_hdrs_completecb, // http_cb      on_headers_complete;
    NULL,                // http_data_cb on_body;
    htp_msg_completecb   // http_cb      on_message_complete;
  };

  http_parser parser;
  parser.data = session_data;
  http_parser_init(&parser, HTTP_REQUEST);
  http_parser_execute(&parser, &parser_settings, buffer, buflen);

  int htperr = parser.http_errno;
  if (htperr != HPE_PAUSED) {
    fprintf(stderr, "Failed to parse HTTP Upgrade request header %s\n:", http_errno_name(htperr));
    PRINT(log_out, "parse_htp")
    return -1;
  }

  PRINT(log_out, "parse_htp2")
  return 0;
}

static void add_stream(http2_session_data *session_data,
                       http2_stream_data *stream_data) {
  PRINT(log_in, "add_stream")

  stream_data->next = session_data->root.next;
  session_data->root.next = stream_data;
  stream_data->prev = &session_data->root;
  if (stream_data->next) {
    stream_data->next->prev = stream_data;
  }

  PRINT(log_out, "add_stream")
}

static void remove_stream(http2_stream_data *stream_data) {
  PRINT(log_in, "remove_stream")

  stream_data->prev->next = stream_data->next;
  if (stream_data->next) {
    stream_data->next->prev = stream_data->prev;
  }

  PRINT(log_out, "remove_stream")
}

static http2_stream_data *create_http2_stream_data(http2_session_data *session_data,
                                                   int32_t stream_id) {
  PRINT(log_in, "create_http2_stream_data")

  http2_stream_data *stream_data;
  stream_data = malloc(sizeof(http2_stream_data));
  memset(stream_data, 0, sizeof(http2_stream_data));
  stream_data->id = stream_id;
  stream_data->fd = -1;

  add_stream(session_data, stream_data);

  PRINT(log_out, "create_http2_stream_data")
  return stream_data;
}

static void delete_http2_stream_data(http2_stream_data *stream_data) {
  PRINT(log_in, "delete_http2_stream_data")

  if (stream_data->fd != -1) {
    close(stream_data->fd);
  }
  // free(stream_data->request_path);
  free(stream_data);

  PRINT(log_out, "delete_http2_stream_data")
}

static int submit_push_promise(nghttp2_session *session, http2_stream_data *stream_data,
        const char *push_path) {
  PRINT(log_in, "submit_push_promise")

  nghttp2_nv hdrs[] = {
    MAKE_NV2(":method", "GET"),
    MAKE_NV(":path", push_path, strlen(push_path)),
    MAKE_NV2(":scheme", "http"),
    MAKE_NV(":authority", stream_data->authority, strlen(stream_data->authority))
  };

  int id = nghttp2_submit_push_promise(session, NGHTTP2_FLAG_END_HEADERS,
          stream_data->id, hdrs, ARRLEN(hdrs), NULL);
  if (id < 0) {
    PRINT(log_out, "submit_push_promise")
    return -1;
  }

  PRINT(log_out, "submit_push_promise2")
  return id;
}

static ssize_t file_read_callback(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data) {
  PRINT(log_in, "file_read_callback")

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

  PRINT(log_out, "file_read_callback")
  return r;
}

static int submit_response(nghttp2_session *session, int32_t stream_id,
        nghttp2_nv *nva, size_t nvlen, int fd) {
  PRINT(log_in, "submit_response")

  int rv;
  nghttp2_data_provider data_prd;
  data_prd.source.fd = fd;
  data_prd.read_callback = file_read_callback;

  PRINT(log_still, "nghttp2_submit_response")
  rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
  if (rv != 0) {
    fprintf(stderr, "Fatal error(%s)\n", nghttp2_strerror(rv));
    PRINT(log_out, "submit_response")
    return -1;
  }

  PRINT(log_out, "submit_response2")
  return 0;
}

static const char ERROR_HTML[] = "<html><head><title>404</title></head>"
                                 "<body><h1>404 Not Found</h1></body></html>";

static int error_reply(nghttp2_session *session,
                       http2_stream_data *stream_data) {
  PRINT(log_in, "error_reply")

  int rv;
  ssize_t writelen;
  int pipefd[2];
  nghttp2_nv hdrs[] = {MAKE_NV2(":status", "404")};

  rv = pipe(pipefd);
  if (rv != 0) {
    perror("pipe failed");
    rv = nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                   stream_data->id,
                                   NGHTTP2_INTERNAL_ERROR);
    if (rv != 0) {
      fprintf(stderr, "Fatal error(%s)\n", nghttp2_strerror(rv));
      PRINT(log_out, "error_reply")
      return -1;
    }

    PRINT(log_out, "error_reply2")
    return 0;
  }

  writelen = write(pipefd[1], ERROR_HTML, sizeof(ERROR_HTML) - 1);
  close(pipefd[1]);

  if (writelen != sizeof(ERROR_HTML) - 1) {
    close(pipefd[0]);

    PRINT(log_out, "error_reply3")
    return -1;
  }

  stream_data->fd = pipefd[0];

  if (submit_response(session, stream_data->id, hdrs, ARRLEN(hdrs),
                    pipefd[0]) != 0) {
    close(pipefd[0]);

    PRINT(log_out, "error_reply4")
    return -1;
  }

  PRINT(log_out, "error_reply5")
  return 0;
}

static int ends_with(const char *s, const char *sub) {
  size_t slen = strlen(s);
  size_t sublen = strlen(sub);
  if (slen < sublen) {
    return 0;
  }
  return memcmp(s + slen - sublen, sub, sublen) == 0;
}

static int check_path(const char *path) {
  /* We don't like '\' in url. */
  PRINT(log_still, "check_path")
  return path[0] && path[0] == '/' && strchr(path, '\\') == NULL &&
         strstr(path, "/../") == NULL && strstr(path, "/./") == NULL &&
         !ends_with(path, "/..") && !ends_with(path, "/.");
}

static int on_request_recv(http2_session_data *session_data, http2_stream_data *stream_data) {
  PRINT(log_in, "on_request_recv")

  int fd;
  nghttp2_nv hdrs[] = {MAKE_NV2(":status", "200")};
  char *rel_path;

  if (session_data->push_path) {
    int id = submit_push_promise(session_data->session, stream_data, session_data->push_path);
    if (id < 0) {
      PRINT(log_out, "on_request_recv2")
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    http2_stream_data *promise = create_http2_stream_data(session_data, id);
    promise->authority = session_data->authority;

    fd = open(session_data->push_path, O_RDONLY);
    if (fd == -1) {
      PRINT(log_out, "on_request_recv3")
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    promise->fd = fd;

    if (submit_response(session_data->session, id, hdrs, ARRLEN(hdrs), fd) != 0) {
      close(fd);
      PRINT(log_out, "on_request_recv4")
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  if (! stream_data->uri) {
    if (error_reply(session_data->session, stream_data) != 0) {
      PRINT(log_out, "on_request_recv5")
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    PRINT(log_out, "on_request_recv6")
    return 0;
  }

  fprintf(stderr, "GET %s\n", stream_data->uri);
  if (! check_path(stream_data->uri)) {
    if (error_reply(session_data->session, stream_data) != 0) {
      PRINT(log_out, "on_request_recv7")
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    PRINT(log_out, "on_request_recv8")
    return 0;
  }
  for (rel_path = stream_data->uri; *rel_path == '/'; ++rel_path)
    ;
  fd = open(rel_path, O_RDONLY);
  if (fd == -1) {
    if (error_reply(session_data->session, stream_data) != 0) {
      PRINT(log_out, "on_request_recv9")
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

    PRINT(log_out, "on_request_recv10")
    return 0;
  }
  stream_data->fd = fd;

  if (submit_response(session_data->session, stream_data->id, hdrs, ARRLEN(hdrs), fd) != 0) {
    close(fd);
    PRINT(log_out, "on_request_recv7")
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  PRINT(log_out, "on_request_recv8")
  return 0;
}

static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  PRINT(log_still, "on_begin_headers_callback")
  return 0;
}

static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data) {
  PRINT(log_still, "on_header_callback")
  return 0;
}

static int on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data) {
  PRINT(log_still, "on_frame_recv_callback")
  return 0;
}

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data) {
  PRINT(log_still, "on_stream_close_callback")
  return 0;
}

static int initialize_h2session(http2_session_data *session_data) {
  PRINT(log_in, "initialize_h2session")

  nghttp2_session_callbacks *callbacks;

  nghttp2_session_callbacks_new(&callbacks);
  nghttp2_session_callbacks_set_on_begin_headers_callback( callbacks, on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);
  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, on_frame_recv_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);

  PRINT(log_still, "nghttp2_session_server_new")
  nghttp2_session_server_new(&session_data->session, callbacks, session_data);
  nghttp2_session_callbacks_del(callbacks);

  nghttp2_settings_entry iv[] = {{NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, 100}};

  PRINT(log_still, "nghttp2_submit_settings")
  int rc = nghttp2_submit_settings(session_data->session, NGHTTP2_FLAG_NONE, iv, ARRLEN(iv));
  if (rc != 0) {
    fprintf(stderr, "nghttp2_submit_settings returned error(%s)\n", nghttp2_strerror(rc));
    PRINT(log_out, "initialize_h2session")
    return -1;
  }

  unsigned char settings[128];
  int len = nghttp2_pack_settings_payload(settings, sizeof(settings), iv, ARRLEN(iv));
  if (len <= 0) {
    fprintf(stderr, "Could not pack SETTINGS: %s\n", nghttp2_strerror(len));
    PRINT(log_out, "initialize_h2session2")
    return -1;
  }

  PRINT(log_still, "nghttp2_session_upgrade2")
  rc = nghttp2_session_upgrade2(session_data->session, settings, len, 0, NULL);
  if (rc != 0) {
    fprintf(stderr, "nghttp2_session_upgrade returned error(%s)\n", nghttp2_strerror(rc));
    PRINT(log_out, "initialize_h2session3")
    return -1;
  }

  PRINT(log_out, "initialize_h2session4")
  return 0;
}

#define BUFSIZE 1024
static int do_read(int sock, struct fd_state *state) {
  PRINT(log_in, "do_read")

  char buf[BUFSIZE];
  int len;

  len = read(sock, buf, sizeof(buf));
  if (len < 0) {
    perror("read failed");
    close(sock);
    PRINT(log_out, "do_read")
    return -1;
  } else if (len == 0) {
    close(sock);
    PRINT(log_out, "do_read2")
    return -1;
  }
  HEXDUMP(buf, len)

  int rc;
  if (state->h2session.session == NULL) {
    rc = parse_htp(&state->h2session, buf, len);
    if (rc < 0) {
      PRINT(log_out, "do_read3")
      return -1;
    }
  } else {
    PRINT(log_in, "nghttp2_session_mem_recv")
    rc = nghttp2_session_mem_recv(state->h2session.session, (unsigned char *)buf, len);
    PRINT(log_out, "nghttp2_session_mem_recv")
    if (rc < 0) {
      fprintf(stderr, "Recevied negative error(%s)\n", nghttp2_strerror(rc));
      PRINT(log_out, "do_read4")
      return -1;
    }
  }

  state->writing = 1;

  PRINT(log_out, "do_read5")
  return 0;
}


static const char SWITCHING[] =
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Connection: Upgrade\r\n"
        "Upgrade: " NGHTTP2_CLEARTEXT_PROTO_VERSION_ID "\r\n"
        "\r\n";

static int do_write(int sock, struct fd_state *state) {
  PRINT(log_in, "do_write")

  int rc;
  int len;
  const unsigned char *sndbuf;

  if (state->h2session.session == NULL) {
    len = strlen(SWITCHING);
    HEXDUMP(SWITCHING, len);
    rc = write(sock, SWITCHING, len);
    if (rc < 0) {
      perror("write failed");
      PRINT(log_out, "do_write")
      return -1;
    }

    rc = initialize_h2session(&state->h2session);
    if (rc < 0) {
      PRINT(log_out, "do_write2")
      return -1;
    }

    http2_stream_data *stream_data = create_http2_stream_data(&state->h2session, 1);
    stream_data->uri = state->h2session.uri;
    stream_data->authority = state->h2session.authority;
    rc = on_request_recv(&state->h2session, stream_data);
    if (rc < 0) {
      PRINT(log_out, "do_write3")
      return -1;
    }
  } else {
    while(1) {
      PRINT(log_in, "nghttp2_session_mem_send")
      rc = nghttp2_session_mem_send(state->h2session.session, &sndbuf);
      PRINT(log_out, "nghttp2_session_mem_send")
      if (rc == 0)
        break;
      if (rc < 0) {
        fprintf(stderr, "nghttp2_session_mem_send returns error(%s)\n", nghttp2_strerror(rc));
        PRINT(log_out, "do_write4")
        return -1;
      }
      HEXDUMP(sndbuf, rc);
      rc = write(sock, sndbuf, rc);
      if (rc < 0) {
        perror("write failed");
        PRINT(log_out, "do_write5")
        return -1;
      }
    }

    if (nghttp2_session_want_read(state->h2session.session) == 0 &&
        nghttp2_session_want_write(state->h2session.session) == 0) {
      PRINT(log_out, "do_write6")
      return -1;
    }
  }

  state->writing = 0;
  PRINT(log_out, "do_write7")
  return 0;
}

int main(int argc, char const *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s port [push_path]\n", argv[0]);
    return 1;
  }

  PRINT(log_in, "main")

  int listener = listen_(atoi(argv[1]), 3);
  if (listener < 0) {
    PRINT(log_out, "main")
    return -1;
  }

  int i, maxfd;
  fd_set readset, writeset;
  fd_state *state[FD_SETSIZE];
  memset(state, 0, sizeof(state));

  while (1) {
    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    FD_SET(listener, &readset);
    maxfd = listener;

    for (i = 0; i < FD_SETSIZE; i ++) {
      if (state[i]) {
        if (i > maxfd)
          maxfd = i;
        FD_SET(i, &readset);
        if (state[i]->writing) {
          FD_SET(i, &writeset);
        }
      }
    }

    if (select(maxfd + 1, &readset, &writeset, NULL, NULL) < 0) {
      perror("select");
      PRINT(log_out, "main2")
      return -1;
    }

    if (FD_ISSET(listener, &readset)) {
      int sock = accept_(listener);
      if (sock > FD_SETSIZE) {
        close(sock);
      } else if (sock > 0) {
        // make_nonblocking(sock);
        state[sock] = alloc_fd_state();
        if (argc > 2) {
          state[sock]->h2session.push_path = argv[2];
        }
      }
    }

    for (i = 0; i < maxfd + 1; i ++) {
      int r = 0;
      if (i == listener)
        continue;

      if (FD_ISSET(i, &readset)) {
        r = do_read(i, state[i]);
      }
      if (r == 0 && FD_ISSET(i, &writeset)) {
        r = do_write(i, state[i]);
      }
      if (r) {    /* recv shutdown or recv / send error */
        free_fd_state(state[i]);
        state[i] = NULL;
        close(i);
      }
    }
  }

  PRINT(log_out, "main3")
  return 0;
}
