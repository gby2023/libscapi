#include <memory.h>
#include <math.h>
#include <numeric>
#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/MHM3PCPartyNS.h"

MHM3PCPartyNS::MHM3PCPartyNS(int pid, shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, PrgFromOpenSSLAES* prg,
							 PrgFromOpenSSLAES* prevPrg, PrgFromOpenSSLAES* nextPrg) :
		SHM3PCPartyNS(pid, nextChannel, prevChannel, prg, prevPrg, nextPrg) {
}

MHM3PCPartyNS::~MHM3PCPartyNS() {
}

int MHM3PCPartyNS::coin_toss(const size_t count, vu_t * results) {
	vu_t * r_head = results;
	size_t due = count, done = 0, inc;
	while (done < due) {
		inc = due - done;
		if (inc > (65536 / sizeof(vu_t))) {
			inc = (65536 / sizeof(vu_t));
		}
		if (0 != coin_toss_unthrottled(inc, r_head)) {
			return -1;
		}
		done += inc;
		r_head += inc;
	}
	return 0;
}

int MHM3PCPartyNS::coin_toss_unthrottled(const size_t count, vu_t * results) {
	RepShrVctr rs;
	rs.first.resize(count);
	rs.second.resize(count);
	if (0 != share_gen_rand(count, rs.first.data(), rs.second.data())) {
		return -1;
	}
	if (0
			!= SHM3PCPartyNS::share_open(-1, count, rs.first.data(),
					rs.second.data(), results)) {
		return -1;
	}
	nextChannel->write((byte*)results, count * sizeof(vu_t));
//	if (0 != gen_randomness()) {
//		return -1;
//	}
	prevChannel->read((byte*)rs.first.data(), count * sizeof(vu_t));
	if (0 != memcmp(rs.first.data(), results, count * sizeof(vu_t))) {
		return -1;
	}
	return 0;
}

int MHM3PCPartyNS::permutate(const size_t count, size_t * index) {
	std::iota(index, index + count, 0);

	size_t bitcnt = (size_t) (1 + log2(count)) * count;
	size_t vutcnt = (bitcnt + (8 * sizeof(vu_t) - 1)) / (8 * sizeof(vu_t));
    Align64Vctr bits(vutcnt, 0);
	if (0 != coin_toss(vutcnt, bits.data())) {
		return -1;
	}

	size_t bitidx = 0;
	vu_t bitmask = 1;
	for (size_t i = 0; i < count - 1; ++i) {
		//use bits to select j out of [i+1, count-1]
		size_t low = i + 1, high = count - 1;
		while (low < high) {
			if (bits[bitidx] & bitmask) {
				low = (low + high) / 2 + 1;
			} else {
				high = (low + high) / 2;
			}

			bitmask <<= 1;
			if (!bitmask) {
				bitidx++;
				bitmask = 1;
			}
		}
		index[i] ^= index[low];
		index[low] ^= index[i];
		index[i] ^= index[low];
	}
	return 0;
}

int MHM3PCPartyNS::share_secret(const int pid, const size_t count,
		const vu_t * v, vu_t * z1, vu_t * z2) {
	const vu_t * v_head = v;
	vu_t * z1_head = z1;
	vu_t * z2_head = z2;
	size_t due = count, done = 0, inc;
	while (done < due) {
		inc = due - done;
		if (inc > 65536) {
			inc = 65536;
		}
		//In case inc > 65536 should send the offset of z1 and z2
		if (0 != share_secret_unthrottled(pid, inc, v_head, z1_head, z2_head)) {
			return -1;
		}
		done += inc;
		v_head += inc;
		z1_head += inc;
		z2_head += inc;

	}
	return 0;
}

int MHM3PCPartyNS::share_secret_unthrottled(const int pid, const size_t count,
		const vu_t * v, vu_t * z1, vu_t * z2) {
	if (0 != SHM3PCPartyNS::share_gen_rand(count, z1, z2)) {
		return -1;
	}
    Align64Vctr a(count), b(count);
	if (0 != share_open(pid, count, z1, z2, a.data())) {
		return -1;
	}
	if (get_pid() == pid) {
#pragma GCC ivdep
		for (size_t i = 0; i < count; ++i) {
			b[i] = a[i] ^ v[i];
		}
		nextChannel->write((byte*)b.data(), count * sizeof(vu_t));
		prevChannel->write((byte*)b.data(), count * sizeof(vu_t));
//		if (0 != gen_randomness()) {
//			return -1;
//		}
	} else {
//		if (0 != gen_randomness()) {
//			return -1;
//		}

		nextChannel->read((byte*)b.data(), count * sizeof(vu_t));
		prevChannel->write((byte*)b.data(), count * sizeof(vu_t));
		prevChannel->read((byte*)a.data(), count * sizeof(vu_t));
#pragma GCC ivdep
		for (size_t i = 0; i < count; ++i) {
			if (a[i] != b[i]) {
				return -1;
			}
		}
	}
	if (0 != SHM3PCPartyNS::scalar_xor(count, z1, z2, b.data(), z1, z2)) {
		return -1;
	}
	return 0;
}

int MHM3PCPartyNS::share_open(const int pid, const size_t count,
		const vu_t * x1, const vu_t * x2, vu_t * v) {
	const vu_t * x1_head = x1;
	const vu_t * x2_head = x2;
	vu_t * v_head = v;
	size_t due = count, done = 0, inc;
	while (done < due) {
		inc = due - done;
		if (inc > (65536 / sizeof(vu_t))) {
			inc = (65536 / sizeof(vu_t));
		}
		if (0 != share_open_unthrottled(pid, inc, x1_head, x2_head, v_head)) {
			return -1;
		}
		done += inc;
		x1_head += inc;
		x2_head += inc;
		v_head += inc;
	}
	return 0;
}

int MHM3PCPartyNS::share_open_unthrottled(const int pid, const size_t count,
		const vu_t * x1, const vu_t * x2, vu_t * v) {
	if (pid < -1 || 2 < pid) { //invalid pid
		return -1;
	}


	bool us = (get_pid() == ((pid + 1) % 3));
	bool ds = (get_pid() == ((pid + 2) % 3));
	bool all(-1 == pid), me(get_pid() == pid);

//	cout<<"us = "<<us<<endl;
//	cout<<"ds = "<<ds<<endl;
//	cout<<"all = "<<all<<endl;
//	cout<<"me = "<<me<<endl;
//
//	cout<<"count = "<<count<<endl;
	if (us || all) { //if open to us/all
//		cout<<"write to next"<<endl;
		nextChannel->write((byte*)x1, count * sizeof(vu_t));

	}

	if (ds || all) { //if open to ds/all
//		cout<<"write to prev"<<endl;
		prevChannel->write((byte*)x2, count * sizeof(vu_t));
	}

	if (me || all) {
		//if open to me/all
        ClrVctr x1_ds(count), x2_us(count);
//		cout<<"read from prev"<<endl;
		prevChannel->read((byte*)x1_ds.data(), count* sizeof(vu_t));
		nextChannel->read((byte*)x2_us.data(), count* sizeof(vu_t));
		if (0 != memcmp(x1_ds.data(), x2_us.data(), count* sizeof(vu_t))) {
		    return -1;
		}
		const vu_t * x3 = x1_ds.data();
#pragma GCC ivdep
		for (size_t i = 0; i < count; ++i) {
			v[i] = x1[i] ^ x2[i] ^ x3[i];
		}
	}

	return 0;
}

int MHM3PCPartyNS::triplet_verification_with_open(const size_t count,
		const vu_t * a1, const vu_t * a2, const vu_t * b1, const vu_t * b2,
		const vu_t * c1, const vu_t * c2) {
    Align64Vctr abc1(3 * count), abc2(3 * count), abc(3 * count);
	memcpy(abc1.data(), a1, count * sizeof(vu_t));
	memcpy(abc1.data() + count, b1, count * sizeof(vu_t));
	memcpy(abc1.data() + 2 * count, c1, count * sizeof(vu_t));
	memcpy(abc2.data(), a2, count * sizeof(vu_t));
	memcpy(abc2.data() + count, b2, count * sizeof(vu_t));
	memcpy(abc2.data() + 2 * count, c2, count * sizeof(vu_t));
	if (0 != share_open(-1, 3 * count, abc1.data(), abc2.data(), abc.data())) {
	    return -1;
	}
#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		if ((abc.data()[i] & abc.data()[i + count])
				!= abc.data()[i + 2 * count]) {
			return -1;
		}
	}
	return 0;
}

int MHM3PCPartyNS::triplet_verification_with_another(const size_t count, const vu_t * a1,
			const vu_t * a2, const vu_t * b1, const vu_t * b2, const vu_t * c1,
			const vu_t * c2, const vu_t * x1, const vu_t * x2, const vu_t * y1,
			const vu_t * y2, const vu_t * z1, const vu_t * z2) {
	const vu_t * a1_head = a1;
	const vu_t * a2_head = a2;
	const vu_t * b1_head = b1;
	const vu_t * b2_head = b2;
	const vu_t * c1_head = c1;
	const vu_t * c2_head = c2;
	const vu_t * x1_head = x1;
	const vu_t * x2_head = x2;
	const vu_t * y1_head = y1;
	const vu_t * y2_head = y2;
	const vu_t * z1_head = z1;
	const vu_t * z2_head = z2;
	size_t due = count, done = 0, inc;
	while (done < due) {
		inc = due - done;
		if (inc > (65536 / sizeof(vu_t))) {
			inc = (65536 / sizeof(vu_t));
		}
		if (0 != triplet_verification_with_another_unthrottled(inc, a1_head, a2_head, b1_head,
				b2_head, c1_head, c2_head, x1_head, x2_head, y1_head, y2_head, z1_head,	z2_head)) {
            return -1;
		}
		done += inc;
		a1_head += inc;
		a2_head += inc;
		b1_head += inc;
		b2_head += inc;
		c1_head += inc;
		c2_head += inc;
		x1_head += inc;
		x2_head += inc;
		y1_head += inc;
		y2_head += inc;
		z1_head += inc;
		z2_head += inc;
	}
	return 0;
}

int MHM3PCPartyNS::triplet_verification_with_another_unthrottled(
		const size_t count, const vu_t * a1, const vu_t * a2, const vu_t * b1,
		const vu_t * b2, const vu_t * c1, const vu_t * c2, const vu_t * x1,
		const vu_t * x2, const vu_t * y1, const vu_t * y2, const vu_t * z1,
		const vu_t * z2) {

    ClrVctr open_rho_sigma(2 * count);
	RepShrVctr rho_sigma;
	rho_sigma.first.resize(2 * count);
	rho_sigma.second.resize(2 * count);
	if (0
			!= share_xor(count, a1, a2, x1, x2, rho_sigma.first.data(),
					rho_sigma.second.data())) {
		return -1;
	}

	if (0
			!= share_xor(count, b1, b2, y1, y2, rho_sigma.first.data() + count,
					rho_sigma.second.data() + count)) {
		return -1;
	}

	if (0
			!= SHM3PCPartyNS::share_open(-1, 2 * count, rho_sigma.first.data(),
					rho_sigma.second.data(), open_rho_sigma.data())) {
		return -1;
	}

	nextChannel->write((byte*)open_rho_sigma.data(), 2 * count * sizeof(vu_t));

//	if (0 != gen_randomness()) {
//		return -1;
//	}

	prevChannel->read((byte*)rho_sigma.first.data(), 2 * count * sizeof(vu_t));

	if (0
			!= memcmp(open_rho_sigma.data(), rho_sigma.first.data(),
					2 * count * sizeof(vu_t))) {
		return -1;
	}

	RepShrVctr & temp(rho_sigma);
	if (0
			!= scalar_and(count, a1, a2, open_rho_sigma.data() + count,
					temp.first.data(), temp.second.data())) {
		return -1;
	} //lower temps have sigma&[a];

	if (0
			!= scalar_and(count, b1, b2, open_rho_sigma.data(),
					temp.first.data() + count, temp.second.data() + count)) {
		return -1;
	} //upper temps have rho&[b];

	if (0
			!= share_xor(count, temp.first.data(), temp.second.data(),
					temp.first.data() + count, temp.second.data() + count,
					temp.first.data(), temp.second.data())) {
		return -1;
	} //lower temps have sigma&[a] ^ rho&[b];

	if (0
			!= share_xor(count, c1, c2, temp.first.data(), temp.second.data(),
					temp.first.data(), temp.second.data())) {
		return -1;
	} //upper temps have [c] ^ sigma&[a] ^ rho&[b];

	if (0
			!= share_xor(count, z1, z2, temp.first.data(), temp.second.data(),
					temp.first.data(), temp.second.data())) {
		return -1;
	} //lower temps have [z] ^ [c] ^ sigma&[a] ^ rho&[b];

#pragma GCC ivdep
	for (size_t i = 0; i < count; ++i) {
		temp.first[i + count] = open_rho_sigma[i] & open_rho_sigma[i + count];
	} //upper temp1 have rho&sigma;

	if (0
			!= scalar_xor(count, temp.first.data(), temp.second.data(),
					temp.first.data() + count, temp.first.data(),
					temp.second.data())) {
		return -1;
	} //lower temps have [z] ^ [c] ^ sigma&[a] ^ rho&[b] ^ rho&sigma;

	nextChannel->write((byte*)temp.second.data(), count * sizeof(vu_t));

//	if (0 != gen_randomness()) {
//		return -1;
//	}

	prevChannel->read((byte*)(temp.second.data() + count), count * sizeof(vu_t));

	if (0
			!= memcmp(temp.first.data(), temp.second.data() + count,
					count * sizeof(vu_t))) {
		return -1;
	}

	return 0;
}

int MHM3PCPartyNS::triplet_generation(const size_t N, const size_t B,
		const size_t C, vu_t * a1, vu_t * a2, vu_t * b1, vu_t * b2, vu_t * c1,
		vu_t * c2) {
	size_t M = N * B + C;
	vu_t * aux_a1, *aux_a2, *aux_b1, *aux_b2, *aux_c1, *aux_c2;
	RepShrVctr a, b, c;
	{
		RepShrVctr temp;
		temp.first.resize(3 * M);
		temp.second.resize(3 * M);

		if (0 != share_gen_rand(2 * M, temp.first.data(), temp.second.data())) {

			return -1;
		}

		aux_a1 = temp.first.data();
		aux_a2 = temp.second.data();
		aux_b1 = temp.first.data() + M;
		aux_b2 = temp.second.data() + M;
		aux_c1 = temp.first.data() + 2 * M;
		aux_c2 = temp.second.data() + 2 * M;

		if (0
				!= SHM3PCPartyNS::share_and(M, aux_a1, aux_a2, aux_b1, aux_b2,
						aux_c1, aux_c2)) {
			return -1;
		}
		a.first.resize(M);
		a.second.resize(M);
		b.first.resize(M);
		b.second.resize(M);
		c.first.resize(M);
		c.second.resize(M);

		//get permutation index
		std::vector<size_t> index(M);
		if (0 != permutate(M, index.data())) {
            return -1;
		}

#pragma GCC ivdep
		for (size_t i = 0; i < M; ++i) {
			a.first[i] = aux_a1[index[i]];
			a.second[i] = aux_a2[index[i]];
			b.first[i] = aux_b1[index[i]];
			b.second[i] = aux_b2[index[i]];
			c.first[i] = aux_c1[index[i]];
			c.second[i] = aux_c2[index[i]];
		}
	}
	if (0
			!= triplet_verification_with_open(C, a.first.data(),
					a.second.data(), b.first.data(), b.second.data(),
					c.first.data(), c.second.data())) {
        return -1;
	}

	aux_a1 = a.first.data() + C;
	aux_a2 = a.second.data() + C;
	aux_b1 = b.first.data() + C;
	aux_b2 = b.second.data() + C;
	aux_c1 = c.first.data() + C;
	aux_c2 = c.second.data() + C;

	for (size_t i = 1; i < B; ++i) {
		if (0
				!= triplet_verification_with_another(N, aux_a1, aux_a2, aux_b1,
						aux_b2, aux_c1, aux_c2, aux_a1 + i * N, aux_a2 + i * N,
						aux_b1 + i * N, aux_b2 + i * N, aux_c1 + i * N,
						aux_c2 + i * N)) {
			return -1;
		}
	}

	memcpy(a1, aux_a1, N);
	memcpy(a2, aux_a2, N);
	memcpy(b1, aux_b1, N);
	memcpy(b2, aux_b2, N);
	memcpy(c1, aux_c1, N);
	memcpy(c2, aux_c2, N);
	return 0;
}
