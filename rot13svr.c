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

#include "log/log.h"

#define MAX_LINE 16384


char
rot13_char(char c) {
    PRINT(log_in, "rot13_char")
    /* We don't want to use isalpha here; setting the locale would change
     * which characters are considered alphabetical. */
    if ((c >= 'a' && c <= 'm') || (c >= 'A' && c <= 'M')) {
        PRINT(log_out, "rot13_char")
        return c + 13;
    }
    else if ((c >= 'n' && c <= 'z') || (c >= 'N' && c <= 'Z')) {
        PRINT(log_out, "rot13_char2")
        return c - 13;
    }
    else {
        PRINT(log_out, "rot13_char3")
        return c;
    }
}

struct fd_state {
    char buffer[MAX_LINE];
    size_t buffer_used;

    int writing;
};

struct fd_state *
alloc_fd_state(void)
{
    PRINT(log_still, "alloc_fd_state")
    struct fd_state *state = malloc(sizeof(struct fd_state));
    if (!state)
        return NULL;
    state->buffer_used = state->writing = 0;
    return state;
}

void
free_fd_state(struct fd_state *state)
{
    PRINT(log_still, "free_fd_state")
    free(state);
}

void
make_nonblocking(int fd)
{
    PRINT(log_still, "make_nonblocking")
    fcntl(fd, F_SETFL, O_NONBLOCK);
}

int
do_read(int fd, struct fd_state *state)
{
    PRINT(log_in, "do_read")

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
                PRINT(log_out, "do_read")
                return -1;
            }
        }

        else if (result == 0) {
            /* no messages are available to be received and the peer has performed an orderly shutdown */
            PRINT(log_out, "do_read2")
            return 1;
        }

        state->buffer_used += result;
    }

    HEXDUMP(state->buffer, state->buffer_used)
    for (i=0; i < state->buffer_used; ++ i)  {
        state->buffer[i] = rot13_char(state->buffer[i]);
    }
    state->writing = 1;

    PRINT(log_out, "do_read3")
    return 0;
}

int
do_write(int fd, struct fd_state *state)
{
    PRINT(log_in, "do_write")

    size_t n_written = 0;
    while (n_written < state->buffer_used) {
        ssize_t result = send(fd, state->buffer + n_written,
                              state->buffer_used - n_written, 0);
        if (result < 0) {
            if (errno == EAGAIN) {
                PRINT(log_out, "do_write")
                return 0;
            }

            PRINT(log_out, "do_write2")
            return -1;
        }
        assert(result != 0);

        n_written += result;
    }

    HEXDUMP(state->buffer, n_written);

    if (n_written == state->buffer_used)
        state->buffer_used = 0;

    state->writing = 0;

    PRINT(log_out, "do_write3")
    return 0;
}

void
run(void)
{
    PRINT(log_in, "run")

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
        PRINT(log_out, "run")
        return;
    }

    if (listen(listener, 16)<0) {
        perror("listen");
        PRINT(log_out, "run2")
        return;
    }

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
            PRINT(log_out, "run3")
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

    PRINT(log_out, "run4")
}

int
main(int c, char **v)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    run();

    return 0;
}
