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
// Created by liork on 04/11/2019.
//

#ifdef __aarch64__
#include "../../include/interactive_mid_protocols/OTExtensionEncrypto.hpp"

OTExtensionEncryptoSender::OTExtensionEncryptoSender(string ipAddress,
                                                     int port) {
  m_socket = Listen(ipAddress, port);
  m_clock = new CLock();
  m_senderThread = new SndThread(m_socket.get(), m_clock);
  m_receiverThread = new RcvThread(m_socket.get(), m_clock);

  m_receiverThread->Start();
  m_senderThread->Start();

  m_cConstSeed = rand();

  m_crypt = new crypto(m_nSecParam, &m_cConstSeed);
  m_sender = new IKNPOTExtSnd(m_crypt, m_receiverThread, m_senderThread);

  m_sender->ComputeBaseOTs(P_FIELD);
}

shared_ptr<OTBatchSOutput> OTExtensionEncryptoSender::transfer(
    OTBatchSInput* input) {
  CBitVector** X = reinterpret_cast<CBitVector**>(
    malloc(sizeof(CBitVector*) * m_nsndvals));
  OTExtensionGeneralSInput* localInput =
  reinterpret_cast<OTExtensionGeneralSInput*>(input);
  // copy the x0Arr and x1Arr from input to CBitVector
  X[0] = new CBitVector();
  X[0]->Copy(localInput->getX0Arr().data(), 0, localInput->getX0ArrSize());
  X[1] = new CBitVector();
  X[1]->Copy(localInput->getX1Arr().data(), 0, localInput->getX1ArrSize());

  MaskingFunction* m_fMaskFct = new XORMasking(m_bitlength);

  m_socket->ResetSndCnt();
  m_socket->ResetRcvCnt();
  // Execute OT sender routine
  int m_nNumOTThreads = 1;
  bool success;
  success = m_sender->send(m_numOTs, m_bitlength, m_nsndvals, X, Snd_OT, Rec_OT,
                           m_nNumOTThreads, m_fMaskFct);
}

OTExtensionEncryptoReceiver::OTExtensionEncryptoReceiver(string ipAddress,
                                                         int port) {
  m_socket = Connect(ipAddress, port);
  m_clock = new CLock();
  m_senderThread = new SndThread(m_socket.get(), m_clock);
  m_receiverThread = new RcvThread(m_socket.get(), m_clock);

  m_receiverThread->Start();
  m_senderThread->Start();

  m_cConstSeed = rand();

  m_crypt = new crypto(m_nSecParam, &this->m_cConstSeed);
  m_receiver = new IKNPOTExtRec(m_crypt, m_receiverThread, m_senderThread);

  m_receiver->ComputeBaseOTs(P_FIELD);
}

shared_ptr<OTBatchROutput> OTExtensionEncryptoReceiver::transfer(
    OTBatchRInput* input) {
  MaskingFunction* m_fMaskFct = new XORMasking(m_bitlength);
  CBitVector choices, response;
  m_numOTs = m_numOTs * ceil_log2(m_nsndvals);
  choices.Create(m_numOTs, m_crypt);
  response.Create(m_numOTs, m_bitlength);
  response.Reset();

  m_socket->ResetSndCnt();
  m_socket->ResetRcvCnt();

  bool success;
  int m_nNumOTThreads = 1;
  // Execute OT receiver routine
  success = m_receiver->receive(m_numOTs, m_bitlength, m_nsndvals, &choices,
                                &response, Snd_OT, Rec_OT, m_nNumOTThreads,
                                m_fMaskFct);
  CBitVector* data(&response);
}

#endif
