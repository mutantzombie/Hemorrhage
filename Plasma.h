//  Plasma.h

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

#ifndef _PLASMA_H_
#define _PLASMA_H_

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/noncopyable.hpp>
#include <deque>
#include <list>
#include <fstream>
#include <string>
#include <thread>

class Plasma : boost::noncopyable
{
public:
  Plasma();
  void addBuffer(const char *start, const char *end);
  void setBitLength(size_t n);
  void setRsa(const char *n, const char *e);
  void start();
  void stop() { m_continue = false; m_cv.notify_one(); }

private:
  typedef std::deque<unsigned char> buffer_t;

  bool checkBuffer(buffer_t& bytes);
  bool checkP(boost::multiprecision::cpp_int const& p) const;
  buffer_t::const_iterator generateString(buffer_t::const_iterator it, buffer_t::const_iterator end, int count, std::string& s) const;
  void saveToFile(buffer_t const& buf);

  bool    m_continue;
  size_t  m_bitLength,
          m_primeBitLength,
          m_primeByteLength;
  boost::multiprecision::cpp_int  m_e,
                                  m_n,
                                  m_primeMinimumThreshold;

  std::list<buffer_t> m_buffers;
  std::string         m_filename;
  std::ofstream       m_file;

  std::condition_variable m_cv;
  std::mutex  m_mutex;
};

#endif
