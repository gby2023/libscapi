#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/MPCMCircuitV.h"
#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/bit_matrix.h"

MPCMCircuitV::MPCMCircuitV(int pid, shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, PrgFromOpenSSLAES* prg,
						   PrgFromOpenSSLAES* prevPrg, PrgFromOpenSSLAES* nextPrg) :
		MPCMCircuit(pid, nextChannel, prevChannel, prg, prevPrg, nextPrg) {
}

MPCMCircuitV::~MPCMCircuitV() {
}

int MPCMCircuitV::m_vcompute(const CircuitSpec & vspec, const size_t vfactor,
		const RepShrVctr & input, RepShrVctr & output) {

	size_t input_size_vu = input.first.size();
	//the replicated share must be of equal size.
	if (input_size_vu != input.second.size()) {
		return -1;
	}

	size_t output_size_vu = vspec.get_output_sequence().size();
	output.first.resize(output_size_vu);
	output.second.resize(output_size_vu);
	return m_vcompute(vspec, vfactor,
			input_size_vu, input.first.data(), input.second.data(),
			output_size_vu, output.first.data(), output.second.data());
}

int MPCMCircuitV::s_vcompute(const CircuitSpec & vspec, const size_t vfactor,
		const RepShrVctr & input, RepShrVctr & output) {

	size_t input_size_vu = input.first.size();
	//the replicated share must be of equal size.
	if (input_size_vu != input.second.size()) {
		return -1;
	}

	size_t output_size_vu = vspec.get_output_sequence().size();
	output.first.resize(output_size_vu);
	output.second.resize(output_size_vu);
	return s_vcompute(vspec, vfactor,
			input_size_vu, input.first.data(), input.second.data(),
			output_size_vu, output.first.data(), output.second.data());
}

int MPCMCircuitV::m_vcompute(const CircuitSpec & vspec, const size_t vfactor,
		const size_t input_size, const vu_t * input1, const vu_t * input2,
		const size_t output_size, vu_t * output1, vu_t * output2) {

	//vfactor must be a multiply of vu_t bit-size.
	if (0 != vfactor % (8 * sizeof(vu_t))) {
		return -1;
	}

	//get the vfactor in terms of byte
	size_t vf = (vfactor / (8 * sizeof(vu_t)));

	//The circuit spec must already vfactor vectorized;
	//hence, spec.get_input_count() must be a multiple of vf
	if (0 != (vspec.get_input_count() % vf)) {
		return -1;
	}

	//The unit input must be greater the 0 and 8 aligned
	size_t unit_input = vspec.get_input_count() / vf;
	if (0 == unit_input || 0 != unit_input % 8) {
		return -1;
	}

	//the input size in bits must be equal to the circuit spec
	if (vspec.get_input_count() != input_size) {
		return -1;
	}

	// create a transposition of the input matrix[vfactor][spec.get_input_count()]
	// into a local temp-input matrix[spec.get_input_count()][vfactor]
	RepShrVctr input_T, output_T;
	input_T.first.resize(input_size, 0);
	input_T.second.resize(input_size, 0);

	if (0
			!= BitMatrix::bit_transpose_byte_matrix((const u_int8_t *) input1,
					vfactor, unit_input / 8,
					(u_int8_t *) input_T.first.data())) {
		return -1;
	}
	if (0
			!= BitMatrix::bit_transpose_byte_matrix((const u_int8_t *) input2,
					vfactor, unit_input / 8,
					(u_int8_t *) input_T.second.data())) {
		return -1;
	}

	//compute the circuit spec on the transposed input
	if (0 != m_compute(vspec, input_T, output_T)) {
		return -1;
	}

	size_t unit_output = (output_size * 8 * sizeof(vu_t)) / vfactor;

	// transpose the computation output shares into output share vector.
	if (0
			!= BitMatrix::bit_transpose_byte_matrix(
					(const u_int8_t *) output_T.first.data(), unit_output,
					vfactor / 8, (u_int8_t *) output1)) {
		return -1;
	}
	if (0
			!= BitMatrix::bit_transpose_byte_matrix(
					(const u_int8_t *) output_T.second.data(), unit_output,
					vfactor / 8, (u_int8_t *) output2)) {
		return -1;
	}

	return 0;
}

int MPCMCircuitV::s_vcompute(const CircuitSpec & vspec, const size_t vfactor,
		const size_t input_size, const vu_t * input1, const vu_t * input2,
		const size_t output_size, vu_t * output1, vu_t * output2) {

	//vfactor must be a multiply of byte bit-size.
	if (0 != vfactor % (8 * sizeof(vu_t))) {
		return -1;
	}

	//get the vfactor in terms of byte
	size_t vf = (vfactor / (8 * sizeof(vu_t)));

	//The circuit spec must already vfactor vectorized;
	//hence, spec.get_input_count() must be a multiple of vf
	if (0 != (vspec.get_input_count() % vf)) {
		return -1;
	}

	//The unit input must be greater the 0 and 8 aligned
	size_t unit_input = vspec.get_input_count() / vf;
	if (0 == unit_input || 0 != unit_input % 8) {
		return -1;
	}

	//the input size in bits must be equal to the circuit spec
	if (vspec.get_input_count() != input_size) {
		return -1;
	}

	// create a transposition of the input matrix[vfactor][spec.get_input_count()]
	// into a local temp-input matrix[spec.get_input_count()][vfactor]
	RepShrVctr input_T, output_T;
	input_T.first.resize(input_size, 0);
	input_T.second.resize(input_size, 0);

	if (0
			!= BitMatrix::bit_transpose_byte_matrix((const u_int8_t *) input1,
					vfactor, unit_input / 8,
					(u_int8_t *) input_T.first.data())) {
		return -1;
	}
	if (0
			!= BitMatrix::bit_transpose_byte_matrix((const u_int8_t *) input2,
					vfactor, unit_input / 8,
					(u_int8_t *) input_T.second.data())) {
		return -1;
	}

	//compute the circuit spec on the transposed input
	if (0 != s_compute(vspec, input_T, output_T)) {
		return -1;
	}

	size_t unit_output = (output_size * 8 * sizeof(vu_t)) / vfactor;

	// transpose the computation output shares into output share vector.
	if (0
			!= BitMatrix::bit_transpose_byte_matrix(
					(const u_int8_t *) output_T.first.data(), unit_output,
					vfactor / 8, (u_int8_t *) output1)) {
		return -1;
	}
	if (0
			!= BitMatrix::bit_transpose_byte_matrix(
					(const u_int8_t *) output_T.second.data(), unit_output,
					vfactor / 8, (u_int8_t *) output2)) {
		return -1;
	}

	return 0;
}
