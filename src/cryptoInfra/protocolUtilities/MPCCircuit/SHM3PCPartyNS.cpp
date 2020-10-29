#include <assert.h>
#include <cstring>
#include <unistd.h>
#include <iostream>
#include <endian.h>

#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/SHM3PCPartyNS.h"
#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/bit_matrix.h"

#include <immintrin.h>

SHM3PCPartyNS::SHM3PCPartyNS(int pid, shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, PrgFromOpenSSLAES* prg,
							 PrgFromOpenSSLAES* prevPrg, PrgFromOpenSSLAES* nextPrg) :
		pid(pid), nextChannel(nextChannel), prevChannel(prevChannel), prg(prg), prevPrg(prevPrg), nextPrg(nextPrg) {
}

SHM3PCPartyNS::~SHM3PCPartyNS() {
}

int SHM3PCPartyNS::get_correlated_randomness(const size_t size, vector<vu_t> & sr) {

    //allocate a buffer for the 2nd randomness
    vector<vu_t> temp(size);

    //generate the local key randomness
    prevPrg->getPRGBytes((byte*)temp.data(), size*sizeof(vu_t));

    //generate the us-pid key randomness
    nextPrg->getPRGBytes((byte*)sr.data(), size*sizeof(vu_t));

    //XOR both buffer into the correlated randomness buffer
#pragma GCC ivdep
    for (size_t i = 0; i < size; ++i) {
        sr[i] ^= temp[i];
    }
    return 0;
}

int SHM3PCPartyNS::get_random_triplets(const size_t size, vector<vu_t> & t0, vector<vu_t> & t1, vu_t * t2) {
	//generate the 1st couple of buffers
	prg->getPRGBytes((byte*)t0.data(), size*sizeof(vu_t));
	prg->getPRGBytes((byte*)t1.data(), size*sizeof(vu_t));

	//the 3rd buffer is a XOR of the 1st couple
#pragma GCC ivdep
	for (size_t i = 0; i < size; ++i) {
		t2[i] = t0[i] ^ t1[i];
	}
	return 0;
}

int SHM3PCPartyNS::init() {
    return 0;
}

int SHM3PCPartyNS::share_secret(const int pid, const size_t count,
		const vu_t * v, vu_t * z1, vu_t * z2) {

	if (0 == count) {
		return 0;
	}

	if (this->get_pid() == pid) { //this is the dealer
		vector<byte> X_pid_2(count);

		//z1 = 		x[pid+0]	= V ^ x[pid+1] ^ x[pid+2].
		//z2 = 		x[pid+1]	random generated.
		//X_pid_2 = x[pid+2]	random generated.

		//Downs share 	= ( x[pid+2] , x[pid+0] )
		//Local share 	= ( x[pid+0] , x[pid+1] )
		//Ups share 	= ( x[pid+1] , x[pid+2] )
		prg->getPRGBytes((byte*)z2, count*sizeof(vu_t));
		prg->getPRGBytes(X_pid_2, 0, count*sizeof(vu_t));
//		if (0 != rt_prg_.get((u_int8_t *) z2, count * sizeof(vu_t))) {
//			return -1;
//		}
//
//		if (0
//				!= rt_prg_.get((u_int8_t *) X_pid_2.data(),
//						count * sizeof(vu_t))) {
//			return -1;
//		}

#pragma GCC ivdep
		for (size_t i = 0; i < count; ++i) {
			z1[i] = v[i] ^ z2[i] ^ X_pid_2[i];
		}


		//TODO there is a bug, since the read data is not going into z1 and z2
		const u_int8_t * whead_X_pid_2 = (const u_int8_t *) X_pid_2.data();
		const u_int8_t * whead_z1 = (const u_int8_t *) z1;
		const u_int8_t * whead_z2 = (const u_int8_t *) z2;
		size_t due = count * sizeof(vu_t), done = 0, inc;
		while (done < due) {
			inc = due - done;
			if (inc > 65536) {
				inc = 65536;
			}
			prevChannel->write(whead_X_pid_2, inc);
			nextChannel->write(whead_z2, inc);
			prevChannel->write(whead_z1, inc);
			nextChannel->write(whead_X_pid_2, inc);
//			gen_randomness();
			whead_X_pid_2 += inc;
			whead_z1 += inc;
			whead_z2 += inc;
			done += inc;
		}
		return 0;
	} else { //other party is the dealer
		bool us = (get_pid() == ((pid + 1) % 3));
		u_int8_t * rhead_z1 = (u_int8_t *) z1;
		u_int8_t * rhead_z2 = (u_int8_t *) z2;
		size_t due = count * sizeof(vu_t), done = 0, inc;
		while (done < due) {
			inc = due - done;
			if (inc > 65536) {
				inc = 65536;
			}
//			gen_randomness();
			if (us) {
				nextChannel->read(rhead_z1, inc);

				nextChannel->read(rhead_z2, inc, us);
			} else {
				prevChannel->read(rhead_z1, inc);

				prevChannel->read(rhead_z2, inc, us);
			}
			rhead_z1 += inc;
			rhead_z2 += inc;
			done += inc;
		}
		return 0;
	}
	return -1;
}

int SHM3PCPartyNS::share_xor(const size_t count, const vu_t * x1,
		const vu_t * x2, const vu_t * y1, const vu_t * y2, vu_t * z1,
		vu_t * z2) {
#pragma GCC ivdep
	for (size_t i = 0; i < count; ) {
#ifdef USE_AVX512
		if((count - i) >= (64/sizeof(vu_t))) {
			__m512i xr, yr, zr;
			xr = _mm512_loadu_si512(x1 + i);
			yr = _mm512_loadu_si512(y1 + i);
			zr = _mm512_xor_si512(xr, yr);
			_mm512_storeu_si512(z1 + i, zr);
			xr = _mm512_loadu_si512(x2 + i);
			yr = _mm512_loadu_si512(y2 + i);
			zr = _mm512_xor_si512(xr, yr);
			_mm512_storeu_si512(z2 + i, zr);
			i += (64/sizeof(vu_t));
			continue;
		}
#endif
		if((count - i) >= (32/sizeof(vu_t))) {
			__m256i xr, yr, zr;
			xr = _mm256_loadu_si256(static_cast<const __m256i *>(static_cast<const void *>(x1 + i)));
			yr = _mm256_loadu_si256(static_cast<const __m256i *>(static_cast<const void *>(y1 + i)));
			zr = _mm256_xor_si256(xr, yr);
			_mm256_storeu_si256(static_cast<__m256i *>(static_cast<void *>(z1 + i)), zr);
			xr = _mm256_loadu_si256(static_cast<const __m256i *>(static_cast<const void *>(x2 + i)));
			yr = _mm256_loadu_si256(static_cast<const __m256i *>(static_cast<const void *>(y2 + i)));
			zr = _mm256_xor_si256(xr, yr);
			_mm256_storeu_si256(static_cast<__m256i *>(static_cast<void *>(z2 + i)), zr);
			i += (32/sizeof(vu_t));
			continue;
		}
		if((count - i) >= (16/sizeof(vu_t))) {
			__m128i xr, yr, zr;
			xr = _mm_loadu_si128(static_cast<const __m128i *>(static_cast<const void *>(x1 + i)));
			yr = _mm_loadu_si128(static_cast<const __m128i *>(static_cast<const void *>(y1 + i)));
			zr = _mm_xor_si128(xr, yr);
			_mm_storeu_si128(static_cast<__m128i *>(static_cast<void *>(z1 + i)), zr);
			xr = _mm_loadu_si128(static_cast<const __m128i *>(static_cast<const void *>(x2 + i)));
			yr = _mm_loadu_si128(static_cast<const __m128i *>(static_cast<const void *>(y2 + i)));
			zr = _mm_xor_si128(xr, yr);
			_mm_storeu_si128(static_cast<__m128i *>(static_cast<void *>(z2 + i)), zr);
			i += (16/sizeof(vu_t));
			continue;
		}
		if((count - i) >= (8/sizeof(vu_t))) {
			*(static_cast<__m64 *>(static_cast<void *>(z1 + i))) = _mm_xor_si64 (*(static_cast<const __m64 *>(static_cast<const void *>(x1 + i))), *(static_cast<const __m64 *>(static_cast<const void *>(y1 + i))));
			*(static_cast<__m64 *>(static_cast<void *>(z2 + i))) = _mm_xor_si64 (*(static_cast<const __m64 *>(static_cast<const void *>(x2 + i))), *(static_cast<const __m64 *>(static_cast<const void *>(y2 + i))));
			i += (8/sizeof(vu_t));
			continue;
		}
		z1[i] = x1[i] ^ y1[i];
		z2[i] = x2[i] ^ y2[i];
		++i;
	}
	return 0;
}

int SHM3PCPartyNS::share_and(const size_t count, const vu_t * x1,
		const vu_t * x2, const vu_t * y1, const vu_t * y2, vu_t * z1,
		vu_t * z2) {

	//Acquire a vector of correlated randomness (alpha ^ beta ^ gamma = 0)
	vector<vu_t> cr(count);
	if (0 != get_correlated_randomness(count, cr)) {
		return -1;
	}
//	cout<<"cr:"<<endl;
//	for (int i=0; i<count; i++){
//		cout<<cr[i]<<" ";
//	}
//	cout<<endl;

#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		z1[i] = cr[i] ^ ((x1[i] & y1[i]) ^ (x1[i] & y2[i]) ^ (x2[i] & y1[i]));
	}
//	cout<<"z1:"<<endl;
//	for (int i=0; i<count; i++){
//		cout<<z1[i]<<" ";
//	}
//	cout<<endl;

	const u_int8_t * whead = (const u_int8_t *) z1;
	u_int8_t * rhead = (u_int8_t *) z2;
	size_t due = count * sizeof(vu_t), done = 0, inc;
//	cout<<"due = "<<due<<endl;
	while (done < due) {
		inc = due - done;

		if (inc > 65536) {
			inc = 65536;
		}
		prevChannel->write(whead, inc);
//		gen_randomness();
		nextChannel->read(rhead, inc);
		whead += inc;
		rhead += inc;
		done += inc;
//		cout<<"read "<<inc<<endl;
	}
//	cout<<"z2:"<<endl;
//	for (int i=0; i<count; i++){
//		cout<<z2[i]<<" ";
//	}
//	cout<<endl;

//    size_t due_size = count * sizeof(vu_t);
//    size_t offset = 0;
//    while (offset < due_size) {
//        size_t step_size = std::min((size_t)INC_SIZE, (due_size - offset));
//
//        const u_int8_t *x1i = (u_int8_t *) x1 + offset;
//        const u_int8_t *x2i = (u_int8_t *) x2 + offset;
//        const u_int8_t *y1i = (u_int8_t *) y1 + offset;
//        const u_int8_t *y2i = (u_int8_t *) y2 + offset;
//        u_int8_t *z1i = (u_int8_t *) z1 + offset;
//        u_int8_t *z2i = (u_int8_t *) z2 + offset;
//        u_int8_t *cr = helper;
//
//        if (0 != get_correlated_randomness(step_size, cr)) {
//            return -1;
//        }
//
//#pragma GCC ivdep
//        for (size_t i = 0; i < step_size; ++i) {
//            z1i[i] = cr[i] ^ ((x1i[i] & y1i[i]) ^ (x1i[i] & y2i[i]) ^ (x2i[i] & y1i[i]));
//        }
//
//        prevChannel->write(whead, step_size);
////		gen_randomness();
//        nextChannel->read(rhead, step_size);
//
//        offset += step_size;
//    }
//
//    return 0;
	return 0;
}

int SHM3PCPartyNS::share_not(const size_t count, const vu_t * x1,
		const vu_t * x2, vu_t * z1, vu_t * z2) {
#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		z1[i] = ~x1[i];
		z2[i] = ~x2[i];
	}
	return 0;
}

int SHM3PCPartyNS::share_open(const int pid, const size_t count,
		const vu_t * x1, const vu_t * x2, vu_t * v) {

	const u_int8_t * whead = (const u_int8_t *)x1;
	u_int8_t * rhead = (u_int8_t *)v;
	size_t due = count * sizeof(vu_t), done = 0, inc;

	while(done < due) {
		inc = due - done;
		if (inc > 65536) {
			inc = 65536;
		}
		if ((get_pid() == ((pid + 1) % 3)) || (-1 == pid)) { // open to us-pid OR open to all parties
			//send my x to us-pid
			nextChannel->write(whead, inc);
		}
		if ((-1 == pid) || (this->get_pid() == pid)) { // open to all parties OR open to me
			//recv x from ds-pid
			prevChannel->read(rhead, inc);
		}
		whead += inc;
		rhead += inc;
		done += inc;
	}

	if ((-1 == pid) || (this->get_pid() == pid)) { // open to all parties OR open to me
#pragma GCC ivdep
		for (size_t i = 0; i < count; ++i) {
			v[i] ^= (x1[i] ^ x2[i]);
		}
	}
	return 0;
}

int SHM3PCPartyNS::scalar_xor(const size_t count, const vu_t * x1,
		const vu_t * x2, const vu_t * s, vu_t * z1, vu_t * z2) {
#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		z1[i] = x1[i] ^ s[i];
		z2[i] = x2[i] ^ s[i];
	}
	return 0;
}

int SHM3PCPartyNS::scalar_and(const size_t count, const vu_t * x1,
		const vu_t * x2, const vu_t * s, vu_t * z1, vu_t * z2) {
#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		z1[i] = x1[i] & s[i];
		z2[i] = x2[i] & s[i];
	}
	return 0;
}

int SHM3PCPartyNS::share_gen_rand(const size_t count, vu_t * z1, vu_t * z2) {
	prevPrg->getPRGBytes((byte*)z1, count*sizeof(vu_t));
	nextPrg->getPRGBytes((byte*)z2, count*sizeof(vu_t));
	return 0;
}

int SHM3PCPartyNS::get_pid() const {
	return pid;
}

int SHM3PCPartyNS::share_set_shuffle(const size_t count, vector<vu_t> & k1, vector<vu_t> & k2,
           vector<vu_t> & v1, vector<vu_t> & v2, vector<vu_t> & r1, vector<vu_t> & r2) {
	switch (pid) {
	case 0:
		if (0 != share_set_shuffle_downstream(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_set_shuffle_passive(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_set_shuffle_upstream(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		break;
	case 1:
		if (0 != share_set_shuffle_upstream(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_set_shuffle_downstream(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_set_shuffle_passive(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		break;
	case 2:
		if (0 != share_set_shuffle_passive(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_set_shuffle_upstream(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_set_shuffle_downstream(count, k1, k2, v1, v2, r1, r2)) {
			return -1;
		}
		/********************************************************************/
		break;
	default:
		return -1;
	}
	return 0;
}

int SHM3PCPartyNS::share_set_shuffle_upstream(const size_t count, vector<vu_t> & kB,
          vector<vu_t> & kC, vector<vu_t> & vB, vector<vu_t> & vC, vector<vu_t> & rB, vector<vu_t> & rC) {
	//Nomenclature per upstream party as P1 (S2)
	//cr1_prg_ was seeded with S12, cr2_prg_ was seeded with S23
	std::vector<vu_t> kBtag(kB), kCtag(kC);
	std::vector<vu_t> vBtag(vB), vCtag(vC);
	std::vector<vu_t> rBtag(rB), rCtag(rC);
	{
        vector<byte> permutation(count - 1);
        prevPrg->getPRGBytes(permutation, 0, (count - 1));

		for (size_t i = 0; i < count - 1; ++i) {
			size_t j = i + (permutation[i] % (count - i));
			if (i == j) {
				continue;
			}
			std::swap(kBtag[i], kBtag[j]);
			std::swap(kCtag[i], kCtag[j]);
			std::swap(vBtag[i], vBtag[j]);
			std::swap(vCtag[i], vCtag[j]);
			std::swap(rBtag[i], rBtag[j]);
			std::swap(rCtag[i], rCtag[j]);
		}
	}

    nextPrg->getPRGBytes((byte*)kC.data(), count*sizeof(vu_t));
    nextPrg->getPRGBytes((byte*)vC.data(), count*sizeof(vu_t));
    nextPrg->getPRGBytes((byte*)rC.data(), count*sizeof(vu_t));

	std::vector<vu_t> kCtag_xor_kC(count), kAtag_xor_kA(count);
	std::vector<vu_t> vCtag_xor_vC(count), vAtag_xor_vA(count);
	std::vector<vu_t> rCtag_xor_rC(count), rAtag_xor_rA(count);
#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		kCtag_xor_kC[i] = kCtag[i] ^ kC[i];
		vCtag_xor_vC[i] = vCtag[i] ^ vC[i];
		rCtag_xor_rC[i] = rCtag[i] ^ rC[i];
	}

	const u_int8_t * kwhead = (const u_int8_t *) kCtag_xor_kC.data();
	u_int8_t * krhead = (u_int8_t *) kAtag_xor_kA.data();
	const u_int8_t * vwhead = (const u_int8_t *) vCtag_xor_vC.data();
	u_int8_t * vrhead = (u_int8_t *) vAtag_xor_vA.data();
	const u_int8_t * rwhead = (const u_int8_t *) rCtag_xor_rC.data();
	u_int8_t * rrhead = (u_int8_t *) rAtag_xor_rA.data();
	size_t due = count * sizeof(vu_t), done = 0, inc;

	while (done < due) {
		inc = due - done;
		if (inc > 65536) {
			inc = 65536;
		}
		prevChannel->write(kwhead, inc);
		prevChannel->read(krhead, inc);

		prevChannel->write(vwhead, inc);
		prevChannel->read(vrhead, inc);

		prevChannel->write(rwhead, inc);
		prevChannel->read(rrhead, inc);

		kwhead += inc;
		krhead += inc;
		vwhead += inc;
		vrhead += inc;
		rwhead += inc;
		rrhead += inc;
		done += inc;
	}

#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		kB[i] = kBtag[i] ^ kAtag_xor_kA[i] ^ kCtag_xor_kC[i];
		vB[i] = vBtag[i] ^ vAtag_xor_vA[i] ^ vCtag_xor_vC[i];
		rB[i] = rBtag[i] ^ rAtag_xor_rA[i] ^ rCtag_xor_rC[i];
	}

	return 0;
}

int SHM3PCPartyNS::share_set_shuffle_downstream(const size_t count, vector<vu_t> & kA,
             vector<vu_t> & kB, vector<vu_t> & vA, vector<vu_t> & vB, vector<vu_t> & rA, vector<vu_t> & rB) {
	//Nomenclature per downstream party = P0 (S1)
	//cr1_prg_ was seeded with S31, cr2_prg_ was seeded with S12
	std::vector<vu_t> kAtag(kA), kBtag(kB);
	std::vector<vu_t> vAtag(vA), vBtag(vB);
	std::vector<vu_t> rAtag(rA), rBtag(rB);
	{
        vector<byte> permutation(count - 1);
        nextPrg->getPRGBytes(permutation, 0, count - 1);

		for (size_t i = 0; i < count - 1; ++i) {
			size_t j = i + (permutation[i] % (count - i));
			if (i == j) {
				continue;
			}
			std::swap(kAtag[i], kAtag[j]);
			std::swap(kBtag[i], kBtag[j]);
			std::swap(vAtag[i], vAtag[j]);
			std::swap(vBtag[i], vBtag[j]);
			std::swap(rAtag[i], rAtag[j]);
			std::swap(rBtag[i], rBtag[j]);
		}
	}

    prevPrg->getPRGBytes((byte*)kA.data(), count*sizeof(vu_t));
    prevPrg->getPRGBytes((byte*)vA.data(), count*sizeof(vu_t));
    prevPrg->getPRGBytes((byte*)rA.data(), count*sizeof(vu_t));

	std::vector<vu_t> kAtag_xor_kA(count), kCtag_xor_kC(count);
	std::vector<vu_t> vAtag_xor_vA(count), vCtag_xor_vC(count);
	std::vector<vu_t> rAtag_xor_rA(count), rCtag_xor_rC(count);
#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		kAtag_xor_kA[i] = kAtag[i] ^ kA[i];
		vAtag_xor_vA[i] = vAtag[i] ^ vA[i];
		rAtag_xor_rA[i] = rAtag[i] ^ rA[i];
	}

	const u_int8_t * kwhead = (const u_int8_t *) kAtag_xor_kA.data();
	u_int8_t * krhead = (u_int8_t *) kCtag_xor_kC.data();
	const u_int8_t * vwhead = (const u_int8_t *) vAtag_xor_vA.data();
	u_int8_t * vrhead = (u_int8_t *) vCtag_xor_vC.data();
	const u_int8_t * rwhead = (const u_int8_t *) rAtag_xor_rA.data();
	u_int8_t * rrhead = (u_int8_t *) rCtag_xor_rC.data();
	size_t due = count * sizeof(vu_t), done = 0, inc;

	while (done < due) {
		inc = due - done;
		if (inc > 65536) {
			inc = 65536;
		}
		nextChannel->write(kwhead, inc);
		nextChannel->read(krhead, inc);

		nextChannel->write(vwhead, inc);
		nextChannel->read(vrhead, inc);

		nextChannel->write(rwhead, inc);
		nextChannel->read(rrhead, inc);

		kwhead += inc;
		krhead += inc;
		vwhead += inc;
		vrhead += inc;
		rwhead += inc;
		rrhead += inc;
		done += inc;
	}

#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		kB[i] = kBtag[i] ^ kAtag_xor_kA[i] ^ kCtag_xor_kC[i];
		vB[i] = vBtag[i] ^ vAtag_xor_vA[i] ^ vCtag_xor_vC[i];
		rB[i] = rBtag[i] ^ rAtag_xor_rA[i] ^ rCtag_xor_rC[i];
	}

	return 0;
}

int SHM3PCPartyNS::share_set_shuffle_passive(const size_t count, vector<vu_t> & kC, vector<vu_t> & kA,
        vector<vu_t> & vC, vector<vu_t> & vA, vector<vu_t> & rC, vector<vu_t> & rA) {
	//Nomenclature per passive party = P2 (S3)
	//cr1_prg_ was seeded with S23; cr2_prg_ was seeded with S31
	nextPrg->getPRGBytes((byte*)kC.data(), count*sizeof(vu_t));
	prevPrg->getPRGBytes((byte*)kA.data(), count*sizeof(vu_t));

    nextPrg->getPRGBytes((byte*)vC.data(), count*sizeof(vu_t));
    prevPrg->getPRGBytes((byte*)vA.data(), count*sizeof(vu_t));

    nextPrg->getPRGBytes((byte*)rC.data(), count*sizeof(vu_t));
    prevPrg->getPRGBytes((byte*)rA.data(), count*sizeof(vu_t));

	return 0;
}

int SHM3PCPartyNS::share_shuffle(const size_t count, vector<vu_t> & k1, vector<vu_t> & k2) {
	switch (pid) {
	case 0:
		if (0 != share_shuffle_downstream(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_shuffle_passive(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_shuffle_upstream(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		break;
	case 1:
		if (0 != share_shuffle_upstream(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_shuffle_downstream(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_shuffle_passive(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		break;
	case 2:
		if (0 != share_shuffle_passive(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_shuffle_upstream(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		if (0 != share_shuffle_downstream(count, k1, k2)) {
			return -1;
		}
		/********************************************************************/
		break;
	default:
		return -1;
	}
	return 0;
}

int SHM3PCPartyNS::share_shuffle_upstream(const size_t count, vector<vu_t> & B, vector<vu_t> & C) {
	//Nomenclature per upstream party as P1 (S2)
	//cr1_prg_ was seeded with S12, cr2_prg_ was seeded with S23
	std::vector<vu_t> Btag(B);
	std::vector<vu_t> Ctag(C);
	{
        vector<byte> permutation(count - 1);
        prevPrg->getPRGBytes(permutation, 0, count - 1);

		for (size_t i = 0; i < count - 1; ++i) {
			size_t j = i + (permutation[i] % (count - i));
			if (i == j) {
				continue;
			}
			std::swap(Btag[i], Btag[j]);
			std::swap(Ctag[i], Ctag[j]);
		}
	}

    nextPrg->getPRGBytes((byte*)C.data(), count*sizeof(vu_t));

	std::vector<vu_t> Ctag_xor_C(count), Atag_xor_A(count);
#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		Ctag_xor_C[i] = Ctag[i] ^ C[i];
	}

	const u_int8_t * whead = (const u_int8_t *) Ctag_xor_C.data();
	u_int8_t * rhead = (u_int8_t *) Atag_xor_A.data();
	size_t due = count * sizeof(vu_t), done = 0, inc;

	while (done < due) {
		inc = due - done;
		if (inc > 65536) {
			inc = 65536;
		}
		prevChannel->write(whead, inc);
		prevChannel->read(rhead, inc);

		whead += inc;
		rhead += inc;
		done += inc;
	}

#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		B[i] = Btag[i] ^ Atag_xor_A[i] ^ Ctag_xor_C[i];
	}

	return 0;
}

int SHM3PCPartyNS::share_shuffle_downstream(const size_t count, vector<vu_t> & A,
                                            vector<vu_t> & B) {
	//Nomenclature per downstream party = P0 (S1)
	//cr1_prg_ was seeded with S31, cr2_prg_ was seeded with S12
	std::vector<vu_t> Atag(A);
	std::vector<vu_t> Btag(B);
	{
        vector<byte> permutation(count - 1);
        nextPrg->getPRGBytes(permutation, 0, count - 1);

		for (size_t i = 0; i < count - 1; ++i) {
			size_t j = i + (permutation[i] % (count - i));
			if (i == j) {
				continue;
			}
			std::swap(Atag[i], Atag[j]);
			std::swap(Btag[i], Btag[j]);
		}
	}

    prevPrg->getPRGBytes((byte*)A.data(), count*sizeof(vu_t));

	std::vector<vu_t> Atag_xor_A(count), Ctag_xor_C(count);
#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		Atag_xor_A[i] = Atag[i] ^ A[i];
	}

	const u_int8_t * whead = (const u_int8_t *) Atag_xor_A.data();
	u_int8_t * rhead = (u_int8_t *) Ctag_xor_C.data();
	size_t due = count * sizeof(vu_t), done = 0, inc;

	while (done < due) {
		inc = due - done;
		if (inc > 65536) {
			inc = 65536;
		}
		nextChannel->write(whead, inc);
		nextChannel->read(rhead, inc);
		whead += inc;
		rhead += inc;
		done += inc;
	}

#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		B[i] = Btag[i] ^ Atag_xor_A[i] ^ Ctag_xor_C[i];
	}

	return 0;
}

int SHM3PCPartyNS::share_shuffle_passive(const size_t count, vector<vu_t> & C, vector<vu_t> & A) {
	//Nomenclature per passive party = P2 (S3)
	prevPrg->getPRGBytes((byte*)C.data(), count*sizeof(vu_t));
	nextPrg->getPRGBytes((byte*)A.data(), count*sizeof(vu_t));
	return 0;
}

int SHM3PCPartyNS::share_set_parity(const size_t count, const vu_t * k1,
		const vu_t * k2, const vu_t * v1, const vu_t * v2, const vu_t * r1,
		const vu_t * r2, const vu_t * kcol_selects, const vu_t * vcol_selects,
		const size_t kselections, vu_t &result) {

	std::vector<vu_t> r1t, r2t;
	if(0 != transpose_randoms(count, r1, r2, r1t, r2t)) {
		return -1;
	}

	result = 0;
	for (size_t i = 0; i < kselections; ++i) {
		vu_t parity_value = 0;
		if (!share_set_parity_cr_select(count, k1, k2, v1, v2, r1t.size(),
				r1t.data(), r2t.data(), kcol_selects[i], vcol_selects[i], i,
				parity_value)) {
			return -1;
		}
		result |= (parity_value << i);
	}
	return 0;
}

int SHM3PCPartyNS::transpose_randoms(const size_t count, const vu_t * r1, const vu_t * r2,
			std::vector<vu_t> & r1t, std::vector<vu_t> & r2t) {
	std::vector<vu_t> temp;

	size_t n = count;
	if (0 != (n % sizeof(vu_t))) {
		n += (sizeof(vu_t) - (n % sizeof(vu_t)));
	}

	temp.assign(r1, r1 + count);
	temp.resize(n, 0);
	for (std::vector<vu_t>::iterator i = temp.begin(); i != temp.end(); ++i) {
		*i = htobe64(*i);
	}
	r1t.resize(n);
	if (0
			!= BitMatrix::bit_transpose_byte_matrix(
					(const u_int8_t *) temp.data(), n, sizeof(vu_t),
					(u_int8_t *) r1t.data())) {
		return -1;
	}
	for (std::vector<vu_t>::iterator i = r1t.begin(); i != r1t.end(); ++i) {
		*i = htobe64(*i);
	}

	temp.assign(r2, r2 + count);
	temp.resize(n, 0);
	for (std::vector<vu_t>::iterator i = temp.begin(); i != temp.end(); ++i) {
		*i = htobe64(*i);
	}
	r2t.resize(n);
	if (0
			!= BitMatrix::bit_transpose_byte_matrix(
					(const u_int8_t *) temp.data(), n, sizeof(vu_t),
					(u_int8_t *) r2t.data())) {
		return -1;
	}
	for (std::vector<vu_t>::iterator i = r2t.begin(); i != r2t.end(); ++i) {
		*i = htobe64(*i);
	}

	return 0;
}

int SHM3PCPartyNS::share_set_parity_cr_select(const size_t count,
		const vu_t * k1, const vu_t * k2, const vu_t * v1, const vu_t * v2,
		const size_t rcount, const vu_t * r1t, const vu_t * r2t,
		const vu_t kcol_select, const vu_t vcol_select, size_t rb_row_selection,
		vu_t &parity_value) {
	//applying the column selection
	std::vector<vu_t> k1_cs(count), k2_cs(count), v1_cs(count), v2_cs(count);

	{ //applying the column selection on key shares
		std::vector<vu_t> kselector(count, kcol_select);
		if (0
				!= scalar_and(count, k1, k2, kselector.data(), k1_cs.data(),
						k2_cs.data())) {
			return -1;
		}
	}

	{ //applying the column selection on value shares
		std::vector<vu_t> vselector(count, vcol_select);
		if (0
				!= scalar_and(count, v1, v2, vselector.data(), v1_cs.data(),
						v2_cs.data())) {
			return -1;
		}
	}

	return share_set_parity_r_select(k1_cs.size(), k1_cs.data(), k2_cs.data(),
			v1_cs.data(), v2_cs.data(), rcount, r1t, r2t, rb_row_selection,
			parity_value);
}

int SHM3PCPartyNS::share_set_parity_r_select(const size_t count,
		const vu_t * k1_cs, const vu_t * k2_cs, const vu_t * v1_cs,
		const vu_t * v2_cs, const size_t rcount, const vu_t * r1t,
		const vu_t * r2t, size_t rb_row_selection, vu_t &parity_value) {

	size_t n_a_vs = rcount / (8 * sizeof(vu_t));

	//In the following section we will sum the k&v shares parity into a vector
	std::vector<vu_t> row_parity_1(n_a_vs, 0), row_parity_2(n_a_vs, 0);

	size_t rp_offset = 0, n = count;
	vu_t rp_mask = ((vu_t) 1 << (8 * sizeof(vu_t) - 1));
	for (size_t i = 0; i < n; ++i) {
		if ((vu_t) __builtin_parityll(k1_cs[i])
				!= (vu_t) __builtin_parityll(v1_cs[i])) {
			row_parity_1[rp_offset] |= rp_mask;
		}
		if ((vu_t) __builtin_parityll(k2_cs[i])
				!= (vu_t) __builtin_parityll(v2_cs[i])) {
			row_parity_2[rp_offset] |= rp_mask;
		}
		if (0 == (rp_mask = rp_mask >> 1)) {
			rp_offset++;
			rp_mask = ((vu_t) 1 << (8 * sizeof(vu_t) - 1));
		}
	}

	//AND the row parities with the current row selection mask
	if (0
			!= share_and(n_a_vs, r1t + (rb_row_selection * n_a_vs),
					r2t + (rb_row_selection * n_a_vs), row_parity_1.data(),
					row_parity_2.data(), row_parity_1.data(),
					row_parity_2.data())) {
		return -1;
	}

	vu_t xall[2];
	xall[0] = xall[1] = 0;
	for (size_t i = 0; i < n_a_vs; ++i) {
		xall[0] ^= row_parity_1[i];
		xall[1] ^= row_parity_2[i];
	}

	if (0 != share_open(-1, 1, xall, xall + 1, &parity_value)) {
		return -1;
	}

	parity_value = (vu_t) __builtin_parityll(parity_value);
	return true;
}
