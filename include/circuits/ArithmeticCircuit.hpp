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
#ifndef CIRCUITS_ARITHMETICCIRCUIT_HPP_
#define CIRCUITS_ARITHMETICCIRCUIT_HPP_

#include <string>
#include <vector>

#include "./TGate.hpp"

/**
 * A software representation of the structure of an arithmetic circuit.
 * The circuit consists of Input, Addition, Multiplication, and Output gates.
 * Technically, a circuit is essentially an array of gates, with some
 * bookkeeping information. Each gate has associated input wires (at most 2) and
 * output wire (at most 1). Input and Output gates also have an associated
 * party. We assume that the gates in the circuit are ordered, i.e., each gate
 * only depends on gates with smaller index.
 *
 */



class ArithmeticCircuit {
 private:
  vector<TGate> gates;
  int nrOfMultiplicationGates = 0;
  int nrOfAdditionGates = 0;
  int nrOfSubtractionGates = 0;
  int nrOfRandomGates = 0;
  int nrOfScalarMultGates = 0;
  int nrOfInputGates = 0;
  int nrOfOutputGates = 0;
  int nrOfSumProductsGates = 0;

  bool isCircuitArranged = false;
  vector<int> layersIndices;

 public:
  ArithmeticCircuit();
  ~ArithmeticCircuit();

  /**
   * This method reads text file and creates an object of ArythmeticCircuit
   * according to the file. This includes creating the gates and other
   * information about the parties involved.
   *
   */
  void readCircuit(const char* fileName);

  void writeToFile(string outputFileName, int numberOfParties);

  // get functions
  int getNrOfMultiplicationGates() { return nrOfMultiplicationGates; }
  int getNrOfAdditionGates() { return nrOfAdditionGates; }
  int getNrSubtractionGates() { return nrOfSubtractionGates; }
  int getNrOfRandomGates() { return nrOfRandomGates; }
  int getNrOfScalarMultGates() { return nrOfScalarMultGates; }
  int getNrOfInputGates() { return nrOfInputGates; }
  int getNrOfOutputGates() { return nrOfOutputGates; }
  int getNrOfSumOfProductsGates() { return nrOfSumProductsGates; }
  int getNrOfGates() {
    return (nrOfMultiplicationGates + nrOfSubtractionGates + nrOfRandomGates +
            nrOfScalarMultGates + nrOfAdditionGates + nrOfSumProductsGates +
            nrOfInputGates + nrOfOutputGates);
  }

  /**
   * This method rearranges the gates to be ordered by depth.
   * After the new order is calculated, it is copied to the vector of gates and
   * replaces the gates that were read from the file.
   *
   */
  void reArrangeCircuit();

  vector<TGate> const& getGates() const { return gates; }
  vector<int> const& getLayers() const { return layersIndices; }
};

#endif  // CIRCUITS_ARITHMETICCIRCUIT_HPP_
