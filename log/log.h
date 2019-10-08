#ifndef LOG_H_
#define LOG_H_

extern int Indent;

extern char *log_in(char *);
extern char *log_out(char *);
extern char *log_still(char *);
extern char *log_hexdump(unsigned char *, int);


#define PRINT(M, S) fprintf(stderr, "%s\n", M((char *)S));

#define HEXDUMP(B, L) fprintf(stderr, "%s\n", log_hexdump((unsigned char *)(B), L));

#endif // LOG_H_
