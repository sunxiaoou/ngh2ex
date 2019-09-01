/* For sockaddr_in */
#include <netinet/in.h>
/* For socket functions */
#include <sys/socket.h>
/* For fcntl */
#include <fcntl.h>
/* for select */
#include <sys/select.h>

#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#define MAX_LINE 16384

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

char
rot13_char(char c)
{
    /* We don't want to use isalpha here; setting the locale would change
     * which characters are considered alphabetical. */
    if ((c >= 'a' && c <= 'm') || (c >= 'A' && c <= 'M'))
        return c + 13;
    else if ((c >= 'n' && c <= 'z') || (c >= 'N' && c <= 'Z'))
        return c - 13;
    else
        return c;
}

struct fd_state {
    char buffer[MAX_LINE];
    size_t buffer_used;

    int writing;
};

struct fd_state *
alloc_fd_state(void)
{
    struct fd_state *state = malloc(sizeof(struct fd_state));
    if (!state)
        return NULL;
    state->buffer_used = state->writing = 0;
    return state;
}

void
free_fd_state(struct fd_state *state)
{
    free(state);
}

void
make_nonblocking(int fd)
{
    fcntl(fd, F_SETFL, O_NONBLOCK);
}

int
do_read(int fd, struct fd_state *state)
{
    fprintf(stderr, "%*c{ do_read\n", 2 * Indent ++, ' ');

    char buf[1024];
    int i;
    ssize_t result;
    while (state->buffer_used < sizeof(state->buffer)) {
        /*
        result = recv(fd, buf, sizeof(buf), 0);
        if (result <= 0)
            break;

        for (i=0; i < result; ++i)  {
            if (state->buffer_used < sizeof(state->buffer))
                state->buffer[state->buffer_used++] = rot13_char(buf[i]);
        }
        */
        result = recv(fd, state->buffer + state->buffer_used,
                sizeof(state->buffer) - state->buffer_used, 0);
        if (result < 0) {
            if (errno == EAGAIN) {
                /* descriptor is marked O_NONBLOCK and no data is waiting to be received */
                break;
            }
            else {
                fprintf(stderr, "%*c} do_read\n", 2 * -- Indent, ' ');
                return -1;
            }
        }
        
        else if (result == 0) {
            /* no messages are available to be received and the peer has performed an orderly shutdown */
            fprintf(stderr, "%*c} do_read2\n", 2 * -- Indent, ' ');
            return 1;
        }

        state->buffer_used += result;
    }

    log_data((unsigned char *)state->buffer, state->buffer_used);
    for (i=0; i < state->buffer_used; ++ i)  {
        state->buffer[i] = rot13_char(state->buffer[i]);
    }
    state->writing = 1;
    
    fprintf(stderr, "%*c} do_read3\n", 2 * -- Indent, ' ');
    return 0;
}

int
do_write(int fd, struct fd_state *state)
{
    fprintf(stderr, "%*c{ do_write\n", 2 * Indent ++, ' ');

    size_t n_written = 0;
    while (n_written < state->buffer_used) {
        ssize_t result = send(fd, state->buffer + n_written,
                              state->buffer_used - n_written, 0);
        if (result < 0) {
            if (errno == EAGAIN) {
                fprintf(stderr, "%*c} do_write\n", 2 * -- Indent, ' ');
                return 0;
            }

            fprintf(stderr, "%*c} do_write2\n", 2 * -- Indent, ' ');    
            return -1;
        }
        assert(result != 0);

        n_written += result;
    }

    log_data((unsigned char *)state->buffer, n_written);

    if (n_written == state->buffer_used)
        state->buffer_used = 0;

    state->writing = 0;

    fprintf(stderr, "%*c} do_write3\n", 2 * -- Indent, ' ');
    return 0;
}

void
run(void)
{
    fprintf(stderr, "%*c{ run\n", 2 * Indent ++, ' ');

    int listener;
    struct fd_state *state[FD_SETSIZE];
    struct sockaddr_in sin;
    int i, maxfd;
    fd_set readset, writeset, exset;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(8080);

    for (i = 0; i < FD_SETSIZE; ++i)
        state[i] = NULL;

    listener = socket(AF_INET, SOCK_STREAM, 0);
    make_nonblocking(listener);

#ifndef WIN32
    {
        int one = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
#endif

    if (bind(listener, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
        perror("bind");
        fprintf(stderr, "%*c} run\n", 2 * -- Indent, ' ');
        return;
    }

    if (listen(listener, 16)<0) {
        perror("listen");
        fprintf(stderr, "%*c} run2\n", 2 * -- Indent, ' ');
        return;
    }

    FD_ZERO(&readset);
    FD_ZERO(&writeset);
    FD_ZERO(&exset);

    while (1) {
        maxfd = listener;

        FD_ZERO(&readset);
        FD_ZERO(&writeset);
        FD_ZERO(&exset);

        FD_SET(listener, &readset);

        for (i=0; i < FD_SETSIZE; ++i) {
            if (state[i]) {
                if (i > maxfd)
                    maxfd = i;
                FD_SET(i, &readset);
                if (state[i]->writing) {
                    FD_SET(i, &writeset);
                }
            }
        }

        if (select(maxfd+1, &readset, &writeset, &exset, NULL) < 0) {
            perror("select");
            fprintf(stderr, "%*c} run3\n", 2 * -- Indent, ' ');
            return;
        }

        if (FD_ISSET(listener, &readset)) {
            struct sockaddr_storage ss;
            socklen_t slen = sizeof(ss);
            int fd = accept(listener, (struct sockaddr*)&ss, &slen);
            if (fd < 0) {
                perror("accept");
            } else if (fd > FD_SETSIZE) {
                close(fd);
            } else {
                make_nonblocking(fd);
                state[fd] = alloc_fd_state();
                assert(state[fd]);/*XXX*/
            }
        }

        for (i=0; i < maxfd+1; ++i) {
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

    fprintf(stderr, "%*c} run4\n", 2 * -- Indent, ' ');
}

int
main(int c, char **v)
{
    fprintf(stderr, "{ main\n"); Indent ++;

    setvbuf(stdout, NULL, _IONBF, 0);

    run();
     -- Indent; fprintf(stderr, "} main\n");
    return 0;
}
