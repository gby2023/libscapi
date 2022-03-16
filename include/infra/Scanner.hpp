/**
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 *
 * Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
 * This file is part of the SCAPI project.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * We request that any publication and/or code referring to and/or based on
 * SCAPI contain an appropriate citation to SCAPI, including a reference to
 * http://crypto.biu.ac.il/SCAPI.
 *
 * Libscapi uses several open source libraries. Please see these projects for
 * any further licensing issues. For more information , See
 * https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
 *
 * %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
 *
 */

// Scanner Class for C++ - Scanner++

// Copyright (C) 2009, 2010, 2011, 2012, 2013, 2014
// scannerpp.sourceforge.net
//
// This file is part of the Scanner++ Library v0.98.  This library is free
// software; you can redistribute it and/or modify it under the
// terms of the GNU Lesser General Public License v3 as published by the
// Free Software Foundation.

// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License v3 for more details.

// You should have received a copy of the GNU Lesser General Public License v3
// along with this library; see the file COPYING.  If not, write to the Free
// Software Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
// USA.

#ifndef INFRA_SCANNER_HPP_
#define INFRA_SCANNER_HPP_

#include <stdlib.h>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <istream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "./File.hpp"

using std::istringstream;
using std::map, std::pair;
using std::stringstream, std::istream, std::cout, std::endl;

namespace scannerpp {
class ConversionError {
 private:
  bool whatInfo;
  std::string what;
  std::string type;

 public:
  explicit ConversionError(std::string _type)
      : whatInfo(false), what(""), type(_type) {}

  ConversionError(std::string _what, std::string _type)
      : whatInfo(true), what(_what), type(_type) {}

  std::string getType() const { return type; }

  std::string getWhat() const { return what; }

  std::string getMessage() const {
    stringstream ss;
    if (whatInfo)
      ss << "value '" << what << "' is not of '" << type << "' type";
    else
      ss << "conversion error for '" << type << "' type";
    return ss.str();
  }
};

class Scanner {
 private:
  istream* input;
  File* inputfile;
  string sep;
  bool isString;

  string discarded;

  string contentString;

 private:
  char nextChar(istream& _input) const {
    int x = _input.get();

    if (x <= 0) throw ConversionError("char");

    return x;
  }

  void put_back(istream** input, string back) const {
    if ((*input)->eof()) {
      // change internal pointer to a renewed istream
      delete (*input);
      (*input) = new istringstream(back);
    } else {
      // just return everything back!

      for (int i = (static_cast<int>(back.length())) - 1; i >= 0; i--) {
        (*input)->putback(back[i]);
        if ((*input)->fail()) {
          cout << "SCANNER ERROR PUTTING BACK CHAR '" << back[i] << "'" << endl;
          cout << "eof bit: '" << (*input)->eof() << "'" << endl;
          cout << "bad bit: '" << (*input)->bad() << "'" << endl;
          cout << "fail bit: '" << (*input)->fail() << "'" << endl;
          exit(1);
        }
      }
    }
  }

 public:
  string getDiscarded() const { return discarded; }

  bool hasNextChar() const;
  char nextChar();

  bool nextCharIs(char c) const;
  bool nextCharIn(string s) const;

  void trimInput();

  explicit Scanner(File* inputfile);
  explicit Scanner(istream* input);
  explicit Scanner(string input);

  Scanner(const Scanner& scanner);

  virtual ~Scanner();

  virtual Scanner& operator=(const Scanner& scanner);

  // useDefaultSeparators: chama o useSeparators para os caracteres:
  // espaco, quebra de linha (\n), tabulacao (\t) e retorno de carro (\r)

  void useDefaultSeparators();

  // useSeparators: equivalente ao useDelimiter de Java
  // a diferenca e que Java trata a string como uma
  // expressao regular, e neste caso o useSeparators
  // apenas considera cada caractere da string separadamente
  // como um separador.

  void useSeparators(string s);
  bool inSeparators(char c) const;

  std::string peekNext() const;
  std::string next();
  std::string nextLine();

  int nextInt();
  int64_t nextLong();
  float nextFloat();
  double nextDouble();

  static int parseInt(string s) {
    Scanner scanner(s);
    return scanner.nextInt();
  }

  static double parseDouble(string s) {
    Scanner scanner(s);
    return scanner.nextDouble();
  }

  static bool trimChar(char c) {
    return (c == ' ') || (c == '\t') || (c == '\n');
  }

  static string trim(string word) {
    if (word.length() == 0) return "";

    int i = 0;
    char c = word.at(i);
    string aux_word = "";

    // removing initial spaces
    while (trimChar(c) && (i < (static_cast<int>(word.length())) - 1)) {
      i++;
      c = word.at(i);
    }

    if (trimChar(c))  // last char
      i++;

    while (i < (static_cast<int>(word.length()))) {
      aux_word += word.at(i);
      i++;
    }

    word = aux_word;

    // may be empty at this point
    if (word.length() == 0) return "";

    // removing final spaces
    i = (static_cast<int>(word.length())) - 1;
    c = word.at(i);

    while (trimChar(c) && (i > 0)) {
      i--;
      c = word.at(i);
    }

    aux_word = "";

    for (int j = 0; j <= i; j++) aux_word += word.at(j);

    return aux_word;
  }

  pair<string, map<string, string> > nextXMLTag();

  bool hasNext() const;

  bool hasNextLine() const { return hasNext(); }

  bool hasNextInt() const {
    int x;
    if (hasNextX(x)) {
      double d;
      if (hasNextX(d)) return (x == d);
    }
    return false;
  }

  bool hasNextLong() const {
    int64_t x;
    if (hasNextX(x)) {
      double d;
      if (hasNextX(d)) return (x == d);
    }
    return false;
  }

  bool hasNextFloat() const {
    float x;
    return hasNextX(x);
  }

  bool hasNextDouble() const {
    double x;
    return hasNextX(x);
  }

  template <class X>
  inline bool hasNextX(X& x) const {
    string s = peekNext();

    if (s == "") return false;

    std::istringstream ss(s);

    return static_cast<bool>(ss >> x);
  }

  string rest();  // Returns the rest of the input as string
};

}  // end namespace scannerpp

#endif  // INFRA_SCANNER_HPP_
