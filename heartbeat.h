#ifndef _HEARTBEAT_H_
#define _HEARTBEAT_H_

#include <openssl/ssl.h>

int tls1_heartbeat_custom(SSL *s, unsigned int hemorrhageLength);

#endif
