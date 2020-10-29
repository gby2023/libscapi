#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <map>

#include <openssl/rand.h>
#include <log4cpp/Category.hh>

#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/circuit_thread.h"

void * ct_proc(void * arg);

circuit_thread::circuit_thread(unsigned int cid, int bufferSize, const int pid,
		shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, const size_t qsize) :
		iq_(qsize), bufferSize(bufferSize), oq_(qsize), cid_(cid), partyID(pid), nextChannel(nextChannel), prevChannel(prevChannel),
		runflag_(false), handle_(0), circuit_(NULL) {

}

circuit_thread::~circuit_thread() {
}

int circuit_thread::start() {
	if (runflag_ || 0 != handle_) {
		cout<<"thread is started."<<endl;
		return -1;
	}

	runflag_ = true;
	int errcode = pthread_create(&handle_, NULL, ct_proc, this);
	if (0 != errcode) {
		char errmsg[256];
		cout<<"pthread_create() failed with error "<<errcode<<" : "<<strerror_r(errcode, errmsg, 256)<<endl;
		runflag_ = false;
		handle_ = 0;
		return -1;
	} else {
		cout<<"started."<<endl;
	}
	return 0;
}

int circuit_thread::stop() {
	if (!runflag_ || 0 == handle_) {
		cout<<"thread is stopped."<<endl;
		return -1;
	}

	runflag_ = false;
	void * retval = NULL;
	struct timespec join_to;
	set_abs_timeout(join_to, 60000000000);
	int errcode = pthread_timedjoin_np(handle_, &retval, &join_to);
	if (0 != errcode) {
		pthread_cancel(handle_);
		char errmsg[256];
		cout<<"pthread_timedjoin_np() failed with error "<<errcode<<" : "<<strerror_r(errcode, errmsg, 256)<<endl;
		return -1;
	}
	return 0;
}

void * ct_proc(void * arg) {
	circuit_thread * ct = (circuit_thread *) arg;
	return ct->run();
}

void * circuit_thread::run() {
    if (0 != init_prgs()) {
        cout<<"prg's init failure."<<endl;
        return NULL;
    }
	if (0 != start_circuit()) {
		cout<<"circuit start failure."<<endl;
		return NULL;
	}

	while (runflag_) {
		perform_task();
	}
	delete circuit_;
	circuit_ = NULL;
	return NULL;
}

int circuit_thread::start_circuit() {
	circuit_ = new MPCMCircuitV(partyID, nextChannel, prevChannel, prg, prevPrg, nextPrg);
	if (0 != circuit_->Init()) {
		cout<<"circuit initialization failure."<<endl;
		return -1;
	}
	return 0;
}

void circuit_thread::perform_task() {
	circuit_thread::ct_task_t task;
	struct timespec to;
	set_abs_timeout(to, 200000000);
	if (0 == iq_.pop_wait(task, &to)) {
		switch (task.ct_type) {
		case circuit_thread::ct_task_t::ct_compare:
			perform_compare_task(task.tid, task.u.comp);
			break;
		case circuit_thread::ct_task_t::ct_circuit:
			perform_circuit_task(task.tid, task.u.circuit);
			break;
		case circuit_thread::ct_task_t::ct_swap:
			perform_swap_task(task.tid, task.u.swap);
			break;
		case circuit_thread::ct_task_t::ct_shuffle:
			perform_shuffle_task(task.tid, task.u.shuffle);
			break;
		default:
			cout<<"task type "<<(u_int32_t) task.ct_type<<" is not supported."<<endl;
			break;
		}
		oq_.push(task);
	}
}

void circuit_thread::perform_compare_task(const size_t tid,
		const comp_task_t & comp) {

	CircMap::const_iterator vc = (*comp.ccm_).find(comp.size);
	if ((*comp.ccm_).end() != vc) {
	    if (op_.first.size() < (comp.size)) {
			op_.first.resize(comp.size);
			op_.second.resize(comp.size);
		}

	    if (comp.malicious) {
			if (0 == circuit_->m_vcompute(vc->second, vc->first, 2 * comp.size, comp.i1, comp.i2, comp.size,
							op_.first.data(), op_.second.data())) {
				if (0 != circuit_->m_share_open(-1, comp.size, op_.first.data(), op_.second.data(), comp.op)) {
					cout<<"comp-"<<vc->first<<" circuit->share_open() failure."<<endl;
				}
			} else {
				cout<<"comp-"<<vc->first<<" circuit.vcompute() failure."<<endl;
			}
		} else {
            if (0 == circuit_->s_vcompute(vc->second, vc->first, 2 * comp.size, comp.i1, comp.i2, comp.size,
                                          op_.first.data(), op_.second.data())) {
                if (0 != circuit_->s_share_open(-1, comp.size, op_.first.data(), op_.second.data(), comp.op)) {
                    cout << "comp-" << vc->first << " circuit->share_open() failure." << endl;
                }

            } else {
                cout << "comp-" << vc->first << " circuit.vcompute() failure." << endl;
            }
		}
	} else {
		cout<<"failed to locate a compare circuit of size "<<comp.size<<"."<<endl;
	}


}


void circuit_thread::perform_circuit_task(const size_t tid, const circuit_task_t & comp) {
	CircMap::const_iterator vc = (*comp.ccm_).begin();
	if ((*comp.ccm_).end() != vc) {
		if (comp.malicious) {
			if (0 != circuit_->m_vcompute(vc->second, vc->first, comp.inputSize, comp.i1, comp.i2, comp.outputSize,
										  comp.o1, comp.o2)) {
				cout<<"comp-"<<vc->first<<" circuit.vcompute() failure."<<endl;
			}
		} else {

			if (0 != circuit_->s_vcompute(vc->second, vc->first, comp.inputSize, comp.i1, comp.i2, comp.outputSize,
										  comp.o1, comp.o2)) {
				cout<<"comp-"<<vc->first<<" circuit.vcompute() failure."<<endl;
			}
		}
	} else {
		cout<<"failed to locate a circuit of size "<<comp.inputSize<<"."<<endl;
	}
}

void circuit_thread::perform_swap_task(const size_t tid, swap_task_t & swap) {
	size_t i1 = swap.low, i0 = swap.high - 2;
	while (i1 < i0) {
		if (0 == swap.cr[(i1 - swap.low + swap.crbase)]) {
			++i1;
			continue;
		}
		if (0 != swap.cr[(i0 - swap.low + swap.crbase)]) {
			--i0;
			continue;
		}

		std::swap(swap.src0[i1], swap.src0[i0]);
		std::swap(swap.src1[i1], swap.src1[i0]);
		std::swap(swap.dest0[i1], swap.dest0[i0]);
		std::swap(swap.dest1[i1], swap.dest1[i0]);
		std::swap(swap.val0[i1], swap.val0[i0]);
		std::swap(swap.val1[i1], swap.val1[i0]);
		std::swap(swap.bit0[i1], swap.bit0[i0]);
		std::swap(swap.bit1[i1], swap.bit1[i0]);
		if (swap.sortWithID){
			std::swap(swap.ids[i1], swap.ids[i0]);
		}
		std::swap(swap.cr[i1 - swap.low + swap.crbase], swap.cr[i0 - swap.low + swap.crbase]);
	}

	int pivot = swap.high - 1;
	if (0 != swap.cr[i1 - swap.low + swap.crbase]) {

		std::swap(swap.src0[i1], swap.src0[pivot]);
		std::swap(swap.src1[i1], swap.src1[pivot]);
		std::swap(swap.dest0[i1], swap.dest0[pivot]);
		std::swap(swap.dest1[i1], swap.dest1[pivot]);
		std::swap(swap.val0[i1], swap.val0[pivot]);
		std::swap(swap.val1[i1], swap.val1[pivot]);
		std::swap(swap.bit0[i1], swap.bit0[pivot]);
		std::swap(swap.bit1[i1], swap.bit1[pivot]);
		if (swap.sortWithID){
			std::swap(swap.ids[i1], swap.ids[pivot]);
		}
		std::swap(swap.cr[i1 - swap.low + swap.crbase], swap.cr[pivot - swap.low + swap.crbase]);
		swap.pivot = i1;
	} else {
		swap.pivot = swap.high - 1;
	}
}

void circuit_thread::perform_shuffle_task(const size_t tid, shuffle_task_t & shuffle) {
//    cout<<"in shuffle thread. start = "<<shuffle.start<<" end = "<<shuffle.end<<endl;
	int elementSize = shuffle.elementSize;
	for (size_t i = shuffle.start; i < shuffle.end ; ++i) {
		//Save the element in the left index in a temp array
		memcpy(shuffle.srcBtagTemp + i * elementSize, shuffle.srcBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.srcCtagTemp + i * elementSize, shuffle.srcCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstBtagTemp + i * elementSize, shuffle.dstBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstCtagTemp + i * elementSize, shuffle.dstCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valBtagTemp + i * elementSize, shuffle.valBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valCtagTemp + i * elementSize, shuffle.valCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		shuffle.bitBtagTemp[i] = shuffle.bitBtag[shuffle.shuffleFinalPermutation[i]];
//		shuffle.bitCtagTemp[i] = shuffle.bitCtag[shuffle.shuffleFinalPermutation[i]];
	}

	for (size_t i = shuffle.start; i < shuffle.end ; ++i) {
		//Save the element in the left index in a temp array
//		memcpy(shuffle.srcBtagTemp + i * elementSize, shuffle.srcBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
		memcpy(shuffle.srcCtagTemp + i * elementSize, shuffle.srcCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstBtagTemp + i * elementSize, shuffle.dstBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstCtagTemp + i * elementSize, shuffle.dstCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valBtagTemp + i * elementSize, shuffle.valBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valCtagTemp + i * elementSize, shuffle.valCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		shuffle.bitBtagTemp[i] = shuffle.bitBtag[shuffle.shuffleFinalPermutation[i]];
//		shuffle.bitCtagTemp[i] = shuffle.bitCtag[shuffle.shuffleFinalPermutation[i]];
	}
	for (size_t i = shuffle.start; i < shuffle.end ; ++i) {
		//Save the element in the left index in a temp array
//		memcpy(shuffle.srcBtagTemp + i * elementSize, shuffle.srcBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.srcCtagTemp + i * elementSize, shuffle.srcCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
		memcpy(shuffle.dstBtagTemp + i * elementSize, shuffle.dstBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstCtagTemp + i * elementSize, shuffle.dstCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valBtagTemp + i * elementSize, shuffle.valBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valCtagTemp + i * elementSize, shuffle.valCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		shuffle.bitBtagTemp[i] = shuffle.bitBtag[shuffle.shuffleFinalPermutation[i]];
//		shuffle.bitCtagTemp[i] = shuffle.bitCtag[shuffle.shuffleFinalPermutation[i]];
	}
	for (size_t i = shuffle.start; i < shuffle.end ; ++i) {
		//Save the element in the left index in a temp array
//		memcpy(shuffle.srcBtagTemp + i * elementSize, shuffle.srcBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.srcCtagTemp + i * elementSize, shuffle.srcCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstBtagTemp + i * elementSize, shuffle.dstBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
		memcpy(shuffle.dstCtagTemp + i * elementSize, shuffle.dstCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valBtagTemp + i * elementSize, shuffle.valBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valCtagTemp + i * elementSize, shuffle.valCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		shuffle.bitBtagTemp[i] = shuffle.bitBtag[shuffle.shuffleFinalPermutation[i]];
//		shuffle.bitCtagTemp[i] = shuffle.bitCtag[shuffle.shuffleFinalPermutation[i]];
	}
	for (size_t i = shuffle.start; i < shuffle.end ; ++i) {
		//Save the element in the left index in a temp array
//		memcpy(shuffle.srcBtagTemp + i * elementSize, shuffle.srcBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.srcCtagTemp + i * elementSize, shuffle.srcCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstBtagTemp + i * elementSize, shuffle.dstBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstCtagTemp + i * elementSize, shuffle.dstCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
		memcpy(shuffle.valBtagTemp + i * elementSize, shuffle.valBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valCtagTemp + i * elementSize, shuffle.valCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		shuffle.bitBtagTemp[i] = shuffle.bitBtag[shuffle.shuffleFinalPermutation[i]];
//		shuffle.bitCtagTemp[i] = shuffle.bitCtag[shuffle.shuffleFinalPermutation[i]];
	}
	for (size_t i = shuffle.start; i < shuffle.end ; ++i) {
		//Save the element in the left index in a temp array
//		memcpy(shuffle.srcBtagTemp + i * elementSize, shuffle.srcBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.srcCtagTemp + i * elementSize, shuffle.srcCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstBtagTemp + i * elementSize, shuffle.dstBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstCtagTemp + i * elementSize, shuffle.dstCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valBtagTemp + i * elementSize, shuffle.valBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
		memcpy(shuffle.valCtagTemp + i * elementSize, shuffle.valCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		shuffle.bitBtagTemp[i] = shuffle.bitBtag[shuffle.shuffleFinalPermutation[i]];
//		shuffle.bitCtagTemp[i] = shuffle.bitCtag[shuffle.shuffleFinalPermutation[i]];
	}
	for (size_t i = shuffle.start; i < shuffle.end ; ++i) {
		//Save the element in the left index in a temp array
//		memcpy(shuffle.srcBtagTemp + i * elementSize, shuffle.srcBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.srcCtagTemp + i * elementSize, shuffle.srcCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstBtagTemp + i * elementSize, shuffle.dstBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstCtagTemp + i * elementSize, shuffle.dstCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valBtagTemp + i * elementSize, shuffle.valBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valCtagTemp + i * elementSize, shuffle.valCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
		shuffle.bitBtagTemp[i] = shuffle.bitBtag[shuffle.shuffleFinalPermutation[i]];
//		shuffle.bitCtagTemp[i] = shuffle.bitCtag[shuffle.shuffleFinalPermutation[i]];
	}
	for (size_t i = shuffle.start; i < shuffle.end ; ++i) {
		//Save the element in the left index in a temp array
//		memcpy(shuffle.srcBtagTemp + i * elementSize, shuffle.srcBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.srcCtagTemp + i * elementSize, shuffle.srcCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstBtagTemp + i * elementSize, shuffle.dstBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.dstCtagTemp + i * elementSize, shuffle.dstCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valBtagTemp + i * elementSize, shuffle.valBtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		memcpy(shuffle.valCtagTemp + i * elementSize, shuffle.valCtag + shuffle.shuffleFinalPermutation[i] * elementSize, elementSize);
//		shuffle.bitBtagTemp[i] = shuffle.bitBtag[shuffle.shuffleFinalPermutation[i]];
		shuffle.bitCtagTemp[i] = shuffle.bitCtag[shuffle.shuffleFinalPermutation[i]];
	}
}

void circuit_thread::set_abs_timeout(struct timespec & to, u_int64_t ns) {
	clock_gettime(CLOCK_REALTIME, &to);
	to.tv_nsec += ns;
	to.tv_sec += to.tv_nsec / 1000000000;
	to.tv_nsec %= 1000000000;
}

int circuit_thread::init_prgs() {
    prg = new PrgFromOpenSSLAES(bufferSize/16+1);

    auto key0 = prg->generateKey(128);
    prg->setKey(key0);

    cout<<"generate key"<<endl;
    auto tempKey = prg->getRandom128();


    nextPrg = new PrgFromOpenSSLAES(20*bufferSize/16+1);
    prevPrg = new PrgFromOpenSSLAES(20*bufferSize/16+1);

    //Initialise the prgs - send keys between the parties
    SecretKey key((byte*)&tempKey, 16, "");
    nextPrg->setKey(key);

    vector<byte> readBuffer(16);
//    sendNext((byte*)&tempKey, readBuffer.data(), 16);
    nextChannel->write((byte*)&tempKey, 16); // write to party 2
    prevChannel->read(readBuffer.data(), 16); // read from party 3
    SecretKey key1(readBuffer.data(), 16, "");
    prevPrg->setKey(key1);
	return 0;
}


