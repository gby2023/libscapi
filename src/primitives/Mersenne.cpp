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
//
// Created by moriya on 01/10/17.
//

#include "../../include/primitives/Mersenne.hpp"

template <>
TemplateField<ZpMersenneIntElement>::TemplateField(int64_t fieldParam) {
  this->fieldParam = 2147483647;
  this->elementSizeInBytes = 4;  // round up to the next byte
  this->elementSizeInBits = 31;

  auto randomKey = prg.generateKey(128);
  prg.setKey(randomKey);

  m_ZERO = new ZpMersenneIntElement(0);
  m_ONE = new ZpMersenneIntElement(1);
}

#ifdef __x86_64__
template <>
TemplateField<ZpMersenneLongElement>::TemplateField(int64_t fieldParam) {
  this->elementSizeInBytes = 8;  // round up to the next byte
  this->elementSizeInBits = 61;

  auto randomKey = prg.generateKey(128);
  prg.setKey(randomKey);

  m_ZERO = new ZpMersenneLongElement(0);
  m_ONE = new ZpMersenneLongElement(1);
}

template <>
TemplateField<ZpMersenne127Element>::TemplateField(int64_t fieldParam) {
  ZpMersenne127Element::init();

  this->elementSizeInBytes = 16;  // round up to the next byte
  this->elementSizeInBits = 127;

  auto randomKey = prg.generateKey(128);
  prg.setKey(randomKey);

  m_ZERO = new ZpMersenne127Element(0);
  m_ONE = new ZpMersenne127Element(1);
}
#endif

template <>
ZpMersenneIntElement
  TemplateField<ZpMersenneIntElement>::GetElement(int64_t b) {
  if (b == 1) {
    return *m_ONE;
  }
  if (b == 0) {
    return *m_ZERO;
  } else {
    ZpMersenneIntElement element(b);
    return element;
  }
}

#ifdef __x86_64__
template <>
ZpMersenne127Element
  TemplateField<ZpMersenne127Element>::GetElement(int64_t b) {
  if (b == 1) {
    return *m_ONE;
  }
  if (b == 0) {
    return *m_ZERO;
  } else {
    ZpMersenne127Element element(b);
    return element;
  }
}

template <>
ZpMersenneLongElement
  TemplateField<ZpMersenneLongElement>::GetElement(int64_t b) {
  if (b == 1) {
    return *m_ONE;
  }
  if (b == 0) {
    return *m_ZERO;
  } else {
    ZpMersenneLongElement element(b);
    return element;
  }
}
#endif

template <>
void TemplateField<ZpMersenneIntElement>::elementToBytes(
  unsigned char *elemenetInBytes, ZpMersenneIntElement &element) {
  memcpy(elemenetInBytes, reinterpret_cast<byte *>(&element.elem), 4);
}

#ifdef __x86_64__
template <>
void TemplateField<ZpMersenneLongElement>::elementToBytes(
    unsigned char *elemenetInBytes, ZpMersenneLongElement &element) {
  memcpy(elemenetInBytes, reinterpret_cast<byte *>(&element.elem), 8);
}

template <>
void TemplateField<ZpMersenne127Element>::elementToBytes(
    unsigned char *elemenetInBytes, ZpMersenne127Element &element) {
  memcpy(elemenetInBytes, reinterpret_cast<byte *>(&element.elem), 16);
}
#endif

template <>
void TemplateField<ZpMersenneIntElement>::elementVectorToByteVector(
    vector<ZpMersenneIntElement> &elementVector, vector<byte> &byteVector) {
  copy_byte_array_to_byte_vector(reinterpret_cast<byte *>(elementVector.data()),
                                 elementVector.size() * elementSizeInBytes,
                                 byteVector, 0);
}

#ifdef __x86_64__
template <>
void TemplateField<ZpMersenneLongElement>::elementVectorToByteVector(
    vector<ZpMersenneLongElement> &elementVector, vector<byte> &byteVector) {
  copy_byte_array_to_byte_vector(reinterpret_cast<byte *>(elementVector.data()),
                                 elementVector.size() * elementSizeInBytes,
                                 byteVector, 0);
}

template <>
void TemplateField<ZpMersenne127Element>::elementVectorToByteVector(
    vector<ZpMersenne127Element> &elementVector, vector<byte> &byteVector) {
  copy_byte_array_to_byte_vector(reinterpret_cast<byte *>(elementVector.data()),
                                 elementVector.size() * elementSizeInBytes,
                                 byteVector, 0);
}
#endif

template <>
ZpMersenneIntElement TemplateField<ZpMersenneIntElement>::bytesToElement(
    unsigned char *elemenetInBytes) {
  return ZpMersenneIntElement((unsigned int)(*(unsigned int *)elemenetInBytes));
}

#ifdef __x86_64__
template <>
ZpMersenneLongElement TemplateField<ZpMersenneLongElement>::bytesToElement(
    unsigned char *elemenetInBytes) {
  return ZpMersenneLongElement(
      static_cast<uint64_t>(*reinterpret_cast<uint64_t *>(elemenetInBytes)));
}

template <>
ZpMersenne127Element TemplateField<ZpMersenne127Element>::bytesToElement(
    unsigned char *elemenetInBytes) {
  return ZpMersenne127Element(
    static_cast<__uint128_t>(
      *reinterpret_cast<__uint128_t *>(elemenetInBytes)));
}

__uint128_t ZpMersenne127Element::p = 0;
#endif
