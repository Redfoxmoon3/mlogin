/* mlogin: minimalistic login                */
/* Copyright (c) 2019  Ørjan Malde           */
/* Released under LGPL, see COPYRIGHT.MLOGIN */

#ifndef HAVE_EXPLICIT_BZERO
void explicit_bzero(void*, size_t);
#endif

extern char ** environ;

void usage(void);
int timingsafe_memcmp(const void *b1, const void *b2, size_t len);
