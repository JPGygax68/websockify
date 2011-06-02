#ifndef __BASE64_H
#define __BASE64_H

typedef unsigned char u_char;

int b64_ntop(u_char const *src, size_t srclength, char *target, size_t targsize);

int b64_pton(char const *src, u_char *target, size_t targsize);

#endif // __BASE64_H
