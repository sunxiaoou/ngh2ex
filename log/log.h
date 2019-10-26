#ifndef LOG_H_
#define LOG_H_

#ifdef __cplusplus
extern "C" {
#endif

extern int Indent;

extern char *log_in(char *);
extern char *log_out(char *);
extern char *log_still(char *);
extern char *log_hexdump(unsigned char *, int);


#define PRINT(M, S) fprintf(stderr, "%s  %s(%d)\n", M((char *)S), __FILE__, __LINE__);

#define HEXDUMP(B, L) fprintf(stderr, "%s\n", log_hexdump((unsigned char *)(B), L));

#ifdef __cplusplus
}
#endif

#endif // LOG_H_
