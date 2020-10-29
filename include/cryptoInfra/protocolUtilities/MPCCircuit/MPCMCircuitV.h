#pragma once

#include "MPCMCircuit.h"

class MPCMCircuitV: public MPCMCircuit {

public:
	MPCMCircuitV(int pid, shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, PrgFromOpenSSLAES* prg,
				 PrgFromOpenSSLAES* prevPrg, PrgFromOpenSSLAES* nextPrg);
	virtual ~MPCMCircuitV();

	int m_vcompute(const CircuitSpec & vspec, const size_t vfactor,
			const RepShrVctr & input, RepShrVctr & output);
	int s_vcompute(const CircuitSpec & vspec, const size_t vfactor,
			const RepShrVctr & input, RepShrVctr & output);

	int m_vcompute(const CircuitSpec & vspec, const size_t vfactor,
			const size_t input_size, const vu_t * input1, const vu_t * input2,
			const size_t output_size, vu_t * output1, vu_t * output2);
	int s_vcompute(const CircuitSpec & vspec, const size_t vfactor,
			const size_t input_size, const vu_t * input1, const vu_t * input2,
			const size_t output_size, vu_t * output1, vu_t * output2);
};
