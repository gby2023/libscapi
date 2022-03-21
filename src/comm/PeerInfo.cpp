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
// Created by roee on 1/16/19.
//

#include "../../include/comm/PeerInfo.h"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cstring>
#include <iostream>

PeerInfo::PeerInfo(int id, const std::string &ip, int port,
                   const std::string &cat, int fd)
    : mId(id), mIp(ip), mPort(port), mFd(fd), mCat(cat) {
  // Initialize sockaddr_in structure
  memset(reinterpret_cast<char *>(&mPeerAddr), 0, sizeof(mPeerAddr));
  mPeerAddr.sin_family = AF_INET;
  mPeerAddr.sin_port = htons(mPort);
  inet_aton(ip.c_str(), &mPeerAddr.sin_addr);
}

PeerInfo::~PeerInfo() {}

PeerInfo::operator std::string() const {
  return (this->mIp) + std::string(":") + std::to_string(this->mPort);
}

std::string PeerInfo::ip() const { return this->mIp; }

int PeerInfo::port() const { return this->mPort; }

const struct sockaddr_in *PeerInfo::addr() const { return &this->mPeerAddr; }

int &PeerInfo::fd() { return this->mFd; }

const int &PeerInfo::fd() const { return this->mFd; }

std::string PeerInfo::cat() const { return mCat; }
