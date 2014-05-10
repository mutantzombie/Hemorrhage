//  Plasma.cpp

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

using boost::multiprecision::cpp_int;

Plasma::Plasma()
  : m_continue(true)
  , m_bitLength(0)
  , m_primeBitLength(0)
  , m_primeByteLength(0)
  , m_e()
  , m_n()
  , m_primeMinimumThreshold()
  , m_filename("hemoglo.bin")
{
}

void
Plasma::addBuffer(const char *start, const char *end)
{
  {
    std::lock_guard<std::mutex> guard(m_mutex);

    m_buffers.emplace_back(start, end);
    std::cout << "Added " << m_buffers.back().size() << " bytes\n";
  }
  m_cv.notify_one();
}

bool
Plasma::checkBuffer(buffer_t& bytes)
{
  if(bytes.size() < m_primeByteLength - 1)
    return false;

  std::string str;
  buffer_t::const_iterator end = bytes.end();
  auto it = generateString(bytes.begin(), end, m_primeByteLength, str);

  cpp_int p(str);

  while(it != end) {
//    std::cout << "try " << std::hex << p << "\n";

    checkP(p);

    for(auto i = m_primeBitLength - 8; i < m_primeBitLength; ++i) {
      bit_unset(p, i);
    }

    if(p.is_zero()) {
      while(p.is_zero() && it != end) {
        auto d = std::distance(it, end);
        std::cout << "zero value\nbytes remaining: " << d << "\n";

        if(d < m_primeByteLength - 2) {
          it = end;
          break;
        }

        it = generateString(it, end, m_primeByteLength, str);
        p.assign(str);
      }

      if(it == end)
        checkP(p);

      continue;
    }

    p <<= 8;
    p += static_cast<unsigned int>(*it);

    ++it;
  }

  return true;
}

bool
Plasma::checkP(cpp_int const& p) const
{
  if(p.is_zero() || !bit_test(p, 0))
    return false;

  if(p < m_primeMinimumThreshold)
    return false;

  cpp_int q,
          remainder;

  divide_qr(m_n, p, q, remainder);
  if(remainder.is_zero()) {
    std::cout << "Found match " << std::hex << p << std::endl;
    abort();
  }

//  std::cout << std::hex << "rem " << remainder << "\n";
  std::cout << std::hex << "miss " << p << "\n";

  return false;
}

Plasma::buffer_t::const_iterator
Plasma::generateString(buffer_t::const_iterator it, buffer_t::const_iterator end, int count, std::string& s) const
{
  it = std::find_if_not(it, end, [](unsigned char c){ return c == 0; });
  if(it == end) {
    s.clear();
    return it;
  }

  std::ostringstream obuf;
  obuf.flags(std::ios_base::hex);
  obuf << "0x" << std::setfill('0');
  obuf.width(2);

  while(it != end && --count > 0) {
    obuf << static_cast<unsigned int>(*it);
    ++it;
  }

  s = obuf.str();

//  std::cout << "test " << s << "\n";

  return it;
}

void
Plasma::setBitLength(size_t n)
{
  std::cout << "Server uses " << n << " bit public key\n";
  m_bitLength = n;
  m_primeBitLength = m_bitLength / 2;
  m_primeByteLength = m_primeBitLength / 8;
  m_primeMinimumThreshold = 1;
  m_primeMinimumThreshold <<= (m_primeBitLength - 16);
  std::cout << "minimum factor " << std::hex << m_primeMinimumThreshold << "\n";
}

void
Plasma::setRsa(const char *n, const char *e)
{
  m_e.assign(e);
  m_n.assign(n);
}

void
Plasma::saveToFile(buffer_t const& buf)
{
  if(!m_file.good())
    return;

  for(auto c : buf)
    m_file << c;
}

void
Plasma::start()
{
  std::unique_lock<std::mutex> lock(m_mutex, std::defer_lock);

  m_file.open(m_filename, std::ios::app | std::ios::binary);

  buffer_t  bytes;
  while(1) {
    lock.lock();

    if(m_buffers.empty()) {
      if(!m_continue) {
        lock.unlock();
        break;
      }

      m_cv.wait(lock, [&]{ return !m_buffers.empty() || !m_continue; });
      lock.unlock();
      std::this_thread::sleep_for(std::chrono::seconds(1));
      continue;
    }

    std::cout << "list size " << m_buffers.size() << "\n";

    bytes = std::move(m_buffers.front());
    m_buffers.pop_front();
    lock.unlock();

    checkBuffer(bytes);
    saveToFile(bytes);
  }
}

