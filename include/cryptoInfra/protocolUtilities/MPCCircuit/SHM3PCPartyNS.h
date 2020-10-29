#pragma once


#include "MPCCircuitProtocol.h"
#include <libscapi/include/primitives/Prg.hpp>
#include <libscapi/include/comm/MPCCommunication.hpp>

class SHM3PCPartyNS: public MPCCircuitProtocol{
private:
	int get_correlated_randomness(const size_t size, vector<vu_t> & sr);
	int get_random_triplets(const size_t size, vector<vu_t> & t0, vector<vu_t> & t1, vu_t * t2);

	int share_set_shuffle_upstream(const size_t count, vector<vu_t> & kB, vector<vu_t> & kC,
								   vector<vu_t> & vB, vector<vu_t> & vC, vector<vu_t> & rB, vector<vu_t> & rC);
	int share_set_shuffle_downstream(const size_t count, vector<vu_t> & kA, vector<vu_t> & kB,
									 vector<vu_t> & vA, vector<vu_t> & vB, vector<vu_t> & rA, vector<vu_t> & rB);
	int share_set_shuffle_passive(const size_t count, vector<vu_t> & kC, vector<vu_t> & kA,
								  vector<vu_t> & vC, vector<vu_t> & vA, vector<vu_t> & rC, vector<vu_t> & rA);

	int share_shuffle_upstream(const size_t count, vector<vu_t> & B, vector<vu_t> & C);
	int share_shuffle_downstream(const size_t count, vector<vu_t> & A, vector<vu_t> & B);
	int share_shuffle_passive(const size_t count, vector<vu_t> & C, vector<vu_t> & A);

	int transpose_randoms(const size_t count, const vu_t * r1, const vu_t * r2,
			std::vector<vu_t> & r1t, std::vector<vu_t> & r2t);
	int share_set_parity_cr_select(const size_t count, const vu_t * k1,
			const vu_t * k2, const vu_t * v1, const vu_t * v2,
			const size_t rcount, const vu_t * r1t, const vu_t * r2t,
			const vu_t kcol_select, const vu_t vcol_select,
			size_t rb_row_selection, vu_t &parity_value);
	int share_set_parity_r_select(const size_t count, const vu_t * k1_cs,
			const vu_t * k2_cs, const vu_t * v1_cs, const vu_t * v2_cs,
			const size_t rcount, const vu_t * r1t, const vu_t * r2t,
			size_t rb_row_selection, vu_t &parity_value);
protected:
	int pid;

	shared_ptr<CommParty> nextChannel;
	shared_ptr<CommParty> prevChannel;
	PrgFromOpenSSLAES* prg;
	PrgFromOpenSSLAES* nextPrg;
	PrgFromOpenSSLAES* prevPrg;

public:
	SHM3PCPartyNS(int pid, shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, PrgFromOpenSSLAES* prg,
			PrgFromOpenSSLAES* prevPrg, PrgFromOpenSSLAES* nextPrg);
	virtual ~SHM3PCPartyNS();

	int init();

	int get_pid() const;

	int share_secret(const int pid, const size_t count, const vu_t * v,
					 vu_t * z1, vu_t * z2);
	int share_open(const int pid, const size_t count, const vu_t * x1,
			const vu_t * x2, vu_t * v);
	int share_xor(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * y1, const vu_t * y2, vu_t * z1, vu_t * z2);
	int share_and(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * y1, const vu_t * y2, vu_t * z1, vu_t * z2);
	int share_not(const size_t count, const vu_t * x1, const vu_t * x2,
			vu_t * z1, vu_t * z2);
	int scalar_xor(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * s, vu_t * z1, vu_t * z2);
	int scalar_and(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * s, vu_t * z1, vu_t * z2);
	int share_gen_rand(const size_t count,vu_t * z1, vu_t * z2);
	int share_set_shuffle(const size_t count, vector<vu_t> & k1, vector<vu_t> & k2,
			vector<vu_t> & v1, vector<vu_t> & v2, vector<vu_t> & r1, vector<vu_t> & r2);
	int share_shuffle(const size_t count, vector<vu_t> & k1, vector<vu_t> & k2);
	int share_set_parity(const size_t count, vu_t * k1, vu_t * k2, vu_t * v1,
			vu_t * v2, vu_t * r1, vu_t * r2);
	int share_set_parity(const size_t count, const vu_t * k1, const vu_t * k2,
			const vu_t * v1, const vu_t * v2, const vu_t * r1, const vu_t * r2,
			const vu_t * kcol_selects, const vu_t * vcol_selects,
			const size_t kselections, vu_t &result);
};
