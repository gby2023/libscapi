#pragma once

#include "lfq.h"
#include "vectorization_defs.h"
#include "MPCMCircuitV.h"

typedef std::map<size_t, CircuitSpec> CircMap;
static constexpr size_t g_qsize = 200;

class circuit_thread {
public:

	typedef struct {
		size_t size;
		key_type *i1, *i2, *op;
		bool malicious;
		CircMap * ccm_;
	} comp_task_t;

	typedef struct {
		size_t inputSize;
		size_t outputSize;
		key_type *i1, *i2;
		key_type *o1, *o2;
		bool malicious;
		CircMap * ccm_;
	} circuit_task_t;

	typedef struct {
		key_type *src0, *src1, *dest0, *dest1, *val0, *val1, *cr;
		byte* bit0, *bit1;
		size_t low, high, crbase;
		size_t pivot;
        int * ids;
        bool sortWithID;
	} swap_task_t;

	typedef struct {
		byte *srcBtagTemp, *srcCtagTemp, *dstBtagTemp, *dstCtagTemp, *valBtagTemp, *valCtagTemp;
		byte *srcBtag, *srcCtag, *dstBtag, *dstCtag, *valBtag, *valCtag;
		int* shuffleFinalPermutation;
		byte* bitBtagTemp, *bitCtagTemp, *bitBtag, *bitCtag;
		size_t start, end;
		int elementSize;
	} shuffle_task_t;

	typedef struct {
		size_t tid;
		enum {
			ct_nil = 0,
			ct_compare,
			ct_swap,
			ct_shuffle,
			ct_circuit,
		} ct_type;
		union {
			comp_task_t comp;
			swap_task_t swap;
			shuffle_task_t shuffle;
			circuit_task_t circuit;
		} u;
	} ct_task_t;

public:
	circuit_thread(unsigned int cid, int bufferSize, const int pid,shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, const size_t qsize);
	~circuit_thread();

	int start();
	int stop();

	lfq<ct_task_t> iq_, oq_;

	friend void * ct_proc(void *);

private:
	unsigned int cid_;
	int bufferSize;
	int partyID;
//	const CircMap & ccm_;
	bool runflag_;
	pthread_t handle_;
	MPCMCircuitV * circuit_;
    shared_ptr<CommParty> nextChannel;  //The channel that connect me to the next party - (myId + 1) % 3
    shared_ptr<CommParty> prevChannel;  //The channel that connect me to the previous party - (myId - 1) % 3

    RepShrVctr op_;
    PrgFromOpenSSLAES* prg, *prevPrg, *nextPrg;

	void * run();
	int start_circuit();
	void perform_task();
	void perform_compare_task(const size_t tid, const comp_task_t & comp);
	void perform_circuit_task(const size_t tid, const circuit_task_t & comp);
	void perform_swap_task(const size_t tid, swap_task_t & swap);
	void perform_shuffle_task(const size_t tid, shuffle_task_t & shuffle);

	int init_prgs();

	static void set_abs_timeout(struct timespec & to, u_int64_t ns);
};
