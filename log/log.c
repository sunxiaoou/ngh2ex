#include <stdio.h>
#include <string.h>

#include "log.h"

int Indent = 0;

char *log_in(char *p) {
  char str[128];
  char *s;

  if (! Indent) {
    sprintf(str, "{ %s", p);
  } else {
  	sprintf(str, "%*c{ %s", 2 * Indent, ' ', p);
  }
  Indent ++;

  return s = str;
}

char *log_out(char *p) {
  char str[128]; 
  char *s;

  if (! -- Indent) {
	  sprintf(str, "} %s", p);
  } else {
  	sprintf(str, "%*c} %s", 2 * Indent, ' ', p);
  }

  return s = str;
}

char *log_still(char *p) {
  char str[128];
  char *s;

  if (! Indent) {
	  sprintf(str, "{ %s }", p);
  } else {
    sprintf(str, "%*c{ %s }", 2 * Indent, ' ', p);
  }

  return s = str;
}

#define APPEND(D) { \
  strcpy(s, D); s += strlen(D); \
}

#define APPEND2(F, D) { \
  sprintf(tmp, F, D); \
  strcpy(s, tmp); s += strlen(tmp); \
}

char *log_hexdump(unsigned char *data, int len) {
  unsigned char c;
  int i, j, maxlen;
  char tmp[128];
  static char str[2048];
  memset(str, 0, sizeof(str));
  char *s = str;
  
  // fprintf(stderr, "len(%d)\n", len);
  APPEND2("len(%d)\n", len)
  for(i = 0; i < len;){
    // fprintf(stderr, "%03x | ", i / 16);
    APPEND2("%03x | ", i / 16);
    maxlen = (len - i > 16) ? 16 : len - i;
    for(j = 0; j < maxlen; j ++){
      if(j && j % 4 == 0)
        // fprintf(stderr, " ");
        APPEND(" ")
      // fprintf(stderr, "%02X", *((unsigned char *)data + i + j));
      APPEND2("%02X", *((unsigned char *)data + i + j))
    }

    for(; j < 16; j ++){
      if(j && j % 4 == 0)
        // fprintf(stderr, " ");
        APPEND(" ")
      // fprintf(stderr, "  ");
      APPEND("  ");
    }

    // fprintf(stderr, " | ");
    APPEND(" | ");
    for(j = 0; j < maxlen; j ++) {
      c = *((unsigned char *)data + i + j);
      if(c >= ' ' && c < 127)
        // fprintf(stderr, "%c", c);
        APPEND2("%c", c)
      else
        // fprintf(stderr, ".");
        APPEND(".");
    }
    for(; j < 16; j ++)
      // fprintf(stderr, " ");
      APPEND(" ");

    i += maxlen;
    if(i < len)
      // fprintf(stderr, "\n");
      APPEND("\n");
  }

  // fprintf(stderr, "\n");
  APPEND("\n");

  return s = str;
}

#if 0
int main() {
  char buf[] = ": slc09wsz.us.or";

  // fprintf(stderr, "%d\n", strlen(buf));
  fprintf(stderr, "%s\n", log_hexdump((unsigned char *)buf, strlen(buf)));
}
#endif