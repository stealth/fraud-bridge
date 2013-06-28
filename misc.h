#ifndef __misc_h__
#define __misc_h__

#include <stdint.h>

int writen(int fd, const void *buf, size_t len);

int readn(int fd, void *buf, size_t len);

unsigned short in_cksum (const unsigned short *, int);

void patch_mss(char *, char *, uint16_t);

#endif

