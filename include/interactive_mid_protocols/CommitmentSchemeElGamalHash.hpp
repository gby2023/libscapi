/**
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
* Copyright (c) 2016 LIBSCAPI (http://crypto.biu.ac.il/SCAPI)
* This file is part of the SCAPI project.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, 
* and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
* FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
* 
* We request that any publication and/or code referring to and/or based on SCAPI contain an appropriate citation to SCAPI, including a reference to
* http://crypto.biu.ac.il/SCAPI.
* 
* Libscapi uses several open source libraries. Please see these projects for any further licensing issues.
* For more information , See https://github.com/cryptobiu/libscapi/blob/master/LICENSE.MD
*
* %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
* 
*/


#pragma once
#include "CommitmentScheme.hpp"
#include "CommitmentSchemeElGamal.hpp"
#include "../../include/primitives/HashOpenSSL.hpp"

/**
* This class implements the committer side of the ElGamal hash commitment. <p>
*
* The pseudo code of this protocol can be found in Protocol 3.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtElGamalHashCommitter : public CmtElGamalCommitterCore, public SecureCommit, public CmtOnByteArray {

	/*
	* runs the following protocol:
	* "Run COMMIT_ELGAMAL to commit to value H(x).
	* For decommitment, send x and the receiver verifies that the commitment was to H(x)".
	*/

private:
	shared_ptr<CryptographicHash> hash;

	/**
	* Returns H(x).
	* @param input should be an instance of CmtByteArrayCommitValue.
	* @param id
	* @return the result of the hash function of the given input.
	*/
	vector<byte> getHashOfX(shared_ptr<CmtCommitValue> input, long id);

public:
	/**
	* This constructor receives as argument the channel and chosses default values of
	* Dlog Group and Cryptographic Hash such that they keep the condition that the size in
	* bytes of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* Otherwise, it throws IllegalArgumentException.
	* An established channel has to be provided by the user of the class.
	* @param channel
	* @throws IOException In case there is a problem in the pre-process phase.
	*/
	CmtElGamalHashCommitter(shared_ptr<CommParty> channel, 
							shared_ptr<DlogGroup> dlog = make_shared<OpenSSLDlogECF2m>("K-283"),
							shared_ptr<CryptographicHash> hash = make_shared<OpenSSLSHA256>());

	/**
	* Runs COMMIT_ElGamal to commit to value H(x).
	* @return the created commitment.
	*/
	shared_ptr<CmtCCommitmentMsg> generateCommitmentMsg(shared_ptr<CmtCommitValue> input, long id) override;

	shared_ptr<CmtCDecommitmentMessage> generateDecommitmentMsg(long id) override;

	/**
	* This function samples random commit value and returns it.
	* @return the sampled commit value
	*/
	shared_ptr<CmtCommitValue> sampleRandomCommitValue() override;

	shared_ptr<CmtCommitValue> generateCommitValue(vector<byte> & x) override {
		return make_shared<CmtByteArrayCommitValue>(make_shared<vector<byte>>(x));
	}

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override;
};

/**
* This class implements the committer side of the ElGamal hash commitment. <p>
*
* The pseudo code of this protocol can be found in Protocol 3.5 of pseudo codes document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*
*
* @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Yael Ejgenberg)
*
*/
class CmtElGamalHashReceiver : public CmtElGamalReceiverCore, public SecureCommit, public CmtOnByteArray {

	/*
	* runs the following protocol:
	* "Run COMMIT_ELGAMAL to commit to value H(x).
	* For decommitment, send x and the receiver verifies that the commitment was to H(x)".
	*/

private:
	shared_ptr<CryptographicHash> hash;

protected:
	shared_ptr<CmtElGamalCommitmentMessage> getCommitmentMsg() override;

public:
	/**
	* This constructor receives as arguments an instance of a Dlog Group and an instance
	* of a Cryptographic Hash such that they keep the condition that the size in bytes
	* of the resulting hash is less than the size in bytes of the order of the DlogGroup.
	* Otherwise, it throws IllegalArgumentException.
	* An established channel has to be provided by the user of the class.
	* @param channel
	* @param dlog
	* @param hash
	*/
	CmtElGamalHashReceiver(shared_ptr<CommParty> channel, 
						   shared_ptr<DlogGroup> dlog = make_shared<OpenSSLDlogECF2m>("K-283"),
						   shared_ptr<CryptographicHash> hash = make_shared<OpenSSLSHA256>());

	/**
	* Verifies that the commitment was to H(x).
	*/
	shared_ptr<CmtCommitValue> verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,	CmtCDecommitmentMessage* decommitmentMsg) override;

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	vector<byte> generateBytesFromCommitValue(CmtCommitValue* value) override; 
};


