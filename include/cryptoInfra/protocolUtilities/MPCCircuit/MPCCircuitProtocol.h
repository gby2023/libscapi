#pragma once

#include <cstdlib>
#include <vector>
#include "vectorization_defs.h"

using namespace std;

class MPCCircuitProtocol {
public:
	virtual int init() = 0;

	virtual int get_pid() const = 0;

	virtual int share_secret(const int pid, const size_t count, const vu_t * v,
			vu_t * z1, vu_t * z2) = 0;
	virtual int share_open(const int pid, const size_t count, const vu_t * x1,
			const vu_t * x2, vu_t * v) = 0;
	virtual int share_xor(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * y1, const vu_t * y2, vu_t * z1, vu_t * z2) = 0;
	virtual int share_and(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * y1, const vu_t * y2, vu_t * z1, vu_t * z2) = 0;
	virtual int share_not(const size_t count, const vu_t * x1, const vu_t * x2,
			vu_t * z1, vu_t * z2) = 0;
	virtual int scalar_xor(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * s, vu_t * z1, vu_t * z2) = 0;
	virtual int scalar_and(const size_t count, const vu_t * x1, const vu_t * x2,
			const vu_t * s, vu_t * z1, vu_t * z2) = 0;
	virtual int share_gen_rand(const size_t count, vu_t * z1, vu_t * z2) = 0;
	virtual int share_set_shuffle(const size_t count, vector<vu_t> & k1, vector<vu_t> & k2,
			vector<vu_t> & v1, vector<vu_t> & v2, vector<vu_t> & r1, vector<vu_t> & r2) = 0;
	virtual int share_shuffle(const size_t count, vector<vu_t> & k1, vector<vu_t> & k2) = 0;
	virtual int share_set_parity(const size_t count, const vu_t * k1,
			const vu_t * k2, const vu_t * v1, const vu_t * v2, const vu_t * r1,
			const vu_t * r2, const vu_t * kcol_selects,
			const vu_t * vcol_selects, const size_t kselections,
			vu_t &result) = 0;
};
