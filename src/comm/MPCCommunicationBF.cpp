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
// Created by moriya on 04/01/17.
//

#include "../../include/comm/MPCCommunicationBF.hpp"

#include <iostream>

#include "../../include/infra/ConfigFile.hpp"

std::vector<std::shared_ptr<ProtocolPartyDataBF> >
MPCCommunicationBF::setCommunication(int id, int numParties,
                                     std::string configFile) {
  std::cout << "in communication" << std::endl;

  std::cout << "num parties = " << numParties << std::endl;
  std::cout << "my id = " << id << std::endl;
  std::vector<std::shared_ptr<ProtocolPartyDataBF> > parties(numParties - 1);

  // open file
  ConfigFile cf(configFile);

  std::string portString, ipString;
  std::vector<int> ports(numParties);
  std::vector<std::string> ips(numParties);

  int counter = 0;
  for (int i = 0; i < numParties; i++) {
    portString = "party_" + std::to_string(i) + "_port";
    ipString = "party_" + std::to_string(i) + "_ip";

    // get partys IPs and ports data
    ports[i] = stoi(cf.Value("", portString));
    ips[i] = cf.Value("", ipString);
  }

  for (int i = 0; i < numParties; i++) {
    u_int16_t self_port = ports[id] + i, peer_port = ports[i] + id;
    if (i < id)
      peer_port -= 1;
    else if (i > id)
      self_port -= 1;
    else
      continue;

    std::cout << i << ": self " << ips[id] << ":" << self_port << " <-> peer "
              << ips[i] << ":" << peer_port << std::endl;
    std::shared_ptr<CommPartyBF> channel =
        std::make_shared<CommPartyTCPSyncedBoostFree>(
            ips[id].c_str(), self_port, ips[i].c_str(), peer_port);
    channel->join(500, 5000);
    std::cout << "channel established" << std::endl;
    parties[counter++] = std::make_shared<ProtocolPartyDataBF>(i, channel);
  }

  return parties;
}
