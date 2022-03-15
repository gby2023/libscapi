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
// Created by hila on 15/09/16.
//

#ifndef CIRCUITS_TGATE_HPP_
#define CIRCUITS_TGATE_HPP_

#include <vector>
#include <string>
using std::vector, std::string;

/**
 * The Gate class is a software representation of a circuit's gate, that is the
 * structure of the aryhtmetic circuit and not the actuall values assigned. It
 * contains a type that performs a logical function on the values of the input
 * wires (input1 and input2)  and assigns that value to the output wire for
 * multiplication and addition gates. The gates may also be of type input/output
 * and for these gates there is the party attribute that represents the owner.
 *
 */

#define INPUT 0
#define OUTPUT 3
#define ADD 1
#define MULT 2
#define RANDOM 4
#define SCALAR 5
#define SUB 6
#define SCALAR_ADD 7
#define SUM_OF_PRODUCTS 8

struct TGate {
  int inputsNum;
  vector<int> inputIndices;
  int input1;  // the 0-gate index, relevant for addition/multiplication/output
  int input2;  // the 1-gate index, relevant for addition/multiplication
  int output;  // the output index of this gate, relevant for
               // input/addition/multiplication
  int gateType;  // the type of the gate, can be logical, that is,
                 // multiplication or addition or an input/output gate.
  int party;  // the owner of the gate, relevant for input/output gate
};

#endif  // CIRCUITS_TGATE_HPP_
