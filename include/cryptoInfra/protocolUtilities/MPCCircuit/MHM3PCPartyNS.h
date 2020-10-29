#pragma once

#include "SHM3PCPartyNS.h"

class MHM3PCPartyNS: public SHM3PCPartyNS {

	int coin_toss_unthrottled(const size_t count, vu_t * results);
	int share_secret_unthrottled(const int pid, const size_t count,
			const vu_t * v, vu_t * z1, vu_t * z2);
	int share_open_unthrottled(const int pid, const size_t count,
			const vu_t * x1, const vu_t * x2, vu_t * v);
	int triplet_verification_with_another_unthrottled(const size_t count,
			const vu_t * a1, const vu_t * a2, const vu_t * b1, const vu_t * b2,
			const vu_t * c1, const vu_t * c2, const vu_t * x1, const vu_t * x2,
			const vu_t * y1, const vu_t * y2, const vu_t * z1, const vu_t * z2);
public:
	MHM3PCPartyNS(int pid, shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, PrgFromOpenSSLAES* prg,
				  PrgFromOpenSSLAES* prevPrg, PrgFromOpenSSLAES* nextPrg);
	virtual ~MHM3PCPartyNS();

	int coin_toss(const size_t count, vu_t * results);
	int permutate(const size_t count, size_t * index);
	virtual int share_secret(const int pid, const size_t count, const vu_t * v,
                             vu_t * z1, vu_t * z2);
	virtual int share_open(const int pid, const size_t count, const vu_t * x1,
			const vu_t * x2, vu_t * v);
	int triplet_verification_with_open(const size_t count, const vu_t * a1,
			const vu_t * a2, const vu_t * b1, const vu_t * b2, const vu_t * c1,
			const vu_t * c2);
	int triplet_verification_with_another(const size_t count, const vu_t * a1,
			const vu_t * a2, const vu_t * b1, const vu_t * b2, const vu_t * c1,
			const vu_t * c2, const vu_t * x1, const vu_t * x2, const vu_t * y1,
			const vu_t * y2, const vu_t * z1, const vu_t * z2);
	int triplet_generation(const size_t N, const size_t B, const size_t C,
			vu_t * a1, vu_t * a2, vu_t * b1, vu_t * b2, vu_t * c1, vu_t * c2);
};
