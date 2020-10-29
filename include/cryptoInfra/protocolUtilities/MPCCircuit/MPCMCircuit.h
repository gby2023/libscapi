#pragma once

#include <semaphore.h>
#include "Spec.h"
#include "MHM3PCPartyNS.h"

class MPCMCircuit {
protected:
	SHM3PCPartyNS shm3pc_;
	MHM3PCPartyNS mhm3pc_;

	RepShrVctr trip_a_, trip_b_, trip_c_;
	size_t required_trips_;
	sem_t get_trips_, got_trips_;
	pthread_t trip_thread_;
	bool trip_flag_;

	int get_triples();

	int load_party_input(const int pid, const size_t input_size,
			RepShrVctr & pinp);
	int process_local_gates(const CircuitSpec::gate_list_t & local_gates,
			const RepShrVctr & input, RepShrVctr & gate_values);
	virtual int m_process_AND_gates(const CircuitSpec::gate_list_t & AND_gates,
			const RepShrVctr & input, RepShrVctr & gate_values);
	virtual int s_process_AND_gates(const CircuitSpec::gate_list_t & AND_gates,
			const RepShrVctr & input, RepShrVctr & gate_values);

	static void select_gin(vu_t & gin1, vu_t & gin2, const size_t gidx,
			const RepShrVctr & input, const RepShrVctr & gate_values);

	RepShrVctr gate_in1_, gate_in2_, gate_out_;
	RepShrVctr gate_values_;
public:
	MPCMCircuit(int pid, shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, PrgFromOpenSSLAES* prg,
				PrgFromOpenSSLAES* prevPrg, PrgFromOpenSSLAES* nextPrg);
	virtual ~MPCMCircuit();
	virtual int Init();

	int m_compute(const CircuitSpec & spec, const RepShrVctr & input,
			RepShrVctr & output);
	int m_share_secret(const int pid, const size_t count,
			const vu_t * v, vu_t* z1, vu_t* z2);
	int m_share_open(const int pid, const size_t count, const vu_t * x1,
			const vu_t * x2, vu_t * v);
	int m_Write(const void * data, const size_t data_size, bool us);
	int m_Read(void * data, const size_t data_size, bool us);

	int s_compute(const CircuitSpec & spec, const RepShrVctr & input,
			RepShrVctr & output);
	int s_share_secret(const int pid, const size_t count,
			const vu_t * v, vu_t * z1, vu_t * z2);
	int s_share_open(const int pid, const size_t count, const vu_t * x1,
			const vu_t * x2, vu_t * v);
	int s_share_gen_rand(const size_t count, vu_t * z1, vu_t * z2);
	int s_Write(const void * data, const size_t data_size, bool us);
	int s_Read(void * data, const size_t data_size, bool us);
	int s_scalar_and(const size_t count, const vu_t * x1, const vu_t * x2,
				const vu_t * s, vu_t * z1, vu_t * z2);
	int s_share_and(const size_t count, const vu_t * x1, const vu_t * x2,
				const vu_t * y1, const vu_t * y2, vu_t * z1, vu_t * z2);
	int s_share_xor(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * y1, const vu_t * y2, vu_t * z1, vu_t * z2);
	int s_share_shuffle(const size_t count, vector<vu_t> & x1, vector<vu_t> & x2);
	int s_share_set_shuffle(const size_t count, vector<vu_t> & x1, vector<vu_t> & x2,
			vector<vu_t> & y1, vector<vu_t> & y2, vector<vu_t> & z1, vector<vu_t> & z2);
	int s_share_set_parity(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * y1, const vu_t * y2, const vu_t * z1, const vu_t * z2,
			const vu_t * kcol, const vu_t * vcol, const size_t kselect,
			vu_t & parity);

	friend void * trip_proc(void * arg);
};
