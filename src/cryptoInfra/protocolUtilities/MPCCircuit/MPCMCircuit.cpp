#include <stdlib.h>
#include <assert.h>

#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/MPCMCircuit.h"

#define TRIPLE_GENERATION_B		2
#define TRIPLE_GENERATION_C		5

void * trip_proc(void * arg) {
    MPCMCircuit * circuit = (MPCMCircuit *) arg;
    circuit->get_triples();
    return NULL;
}

MPCMCircuit::MPCMCircuit(int pid, shared_ptr<CommParty> nextChannel, shared_ptr<CommParty> prevChannel, PrgFromOpenSSLAES* prg,
                         PrgFromOpenSSLAES* prevPrg, PrgFromOpenSSLAES* nextPrg) :
        shm3pc_(pid, nextChannel, prevChannel, prg, prevPrg, nextPrg), mhm3pc_(pid, nextChannel, prevChannel, prg, prevPrg, nextPrg) {
    sem_init(&get_trips_, 0, 0);
    sem_init(&got_trips_, 0, 0);
    trip_flag_ = true;
    assert(0 == pthread_create(&trip_thread_, NULL, trip_proc, this));
}

MPCMCircuit::~MPCMCircuit() {
    trip_flag_ = false;
    required_trips_ = 0;
    sem_post(&get_trips_);
    void * retval;
    struct timespec expiry;
    clock_gettime(CLOCK_REALTIME, &expiry);
    expiry.tv_sec += 1;
    if (0 != pthread_timedjoin_np(trip_thread_, &retval, &expiry)) {
        pthread_cancel(trip_thread_);
    }
}

int MPCMCircuit::Init() {
    if (0 != mhm3pc_.init()) {
        return -1;
    }
    if (0 != shm3pc_.init()) {
        return -1;
    }
    return 0;
}

int MPCMCircuit::get_triples() {
    struct timespec abs_timeout;
    while (trip_flag_) {
        clock_gettime(CLOCK_REALTIME, &abs_timeout);
        abs_timeout.tv_nsec += 200000000;						//add 200 ms
        abs_timeout.tv_sec += abs_timeout.tv_nsec / 1000000000;	//move surplus seconds
        abs_timeout.tv_nsec = abs_timeout.tv_nsec % 1000000000;	//clear surplus seconds
        int error = sem_timedwait(&get_trips_, &abs_timeout);
        if (0 == error) {
            if (0 < required_trips_) {
                if (0
                    == mhm3pc_.triplet_generation(required_trips_,
                                                  TRIPLE_GENERATION_B, TRIPLE_GENERATION_C,
                                                  trip_a_.first.data(), trip_a_.second.data(),
                                                  trip_b_.first.data(), trip_b_.second.data(),
                                                  trip_c_.first.data(), trip_c_.second.data())) {
                    sem_post(&got_trips_);
                }
            }
        }
    }
    return 0;
}

int MPCMCircuit::load_party_input(const int pid, const size_t input_size,
                                  RepShrVctr & pinp) {
    ClrVctr clr_input;

    if (this->mhm3pc_.get_pid() == pid) {
        clr_input.resize(input_size);
        char input_file[256];
        snprintf(input_file, 256, "party_input.%d", pid);
        FILE * pf = fopen(input_file, "r");
        if (NULL == pf) {
            return -1;
        }
        ssize_t nread = fread(clr_input.data(), sizeof(vu_t), input_size, pf);
        fclose(pf);
        if (input_size != (size_t) nread) {
            return -1;
        }
    }

    return this->mhm3pc_.share_secret(pid, input_size, clr_input.data(),
                                      pinp.first.data(), pinp.second.data());
}

int MPCMCircuit::process_local_gates(
        const CircuitSpec::gate_list_t & local_gates, const RepShrVctr & input,
        RepShrVctr & gate_values) {
    if (local_gates.empty()) {
        return 0;
    }

    for (CircuitSpec::gate_list_t::const_iterator i = local_gates.begin();
         i != local_gates.end(); ++i) {

        size_t gin1_idx = i->inp1_;
        const vu_t * gin1_1st = NULL, *gin1_2nd = NULL;
        if (gin1_idx < input.first.size()) {
            gin1_1st = input.first.data() + gin1_idx;
            gin1_2nd = input.second.data() + gin1_idx;
        } else {
            gin1_1st = gate_values.first.data()
                       + (gin1_idx - input.first.size());
            gin1_2nd = gate_values.second.data()
                       + (gin1_idx - input.first.size());
        }

        size_t gout_idx = i->sqnum_ - input.first.size();
        vu_t * gout_1st = gate_values.first.data() + gout_idx, *gout_2nd =
                gate_values.second.data() + gout_idx;

        switch (i->type_) {
            case Gate::gt_not:
                if (0
                    != this->shm3pc_.share_not(1, gin1_1st, gin1_2nd, gout_1st,
                                               gout_2nd)) {
                    return -1;
                }
                break;
            case Gate::gt_xor: {
                size_t gin2_idx = i->inp2_;
                const vu_t * gin2_1st = NULL, *gin2_2nd = NULL;
                if (gin2_idx < input.first.size()) {
                    gin2_1st = input.first.data() + gin2_idx;
                    gin2_2nd = input.second.data() + gin2_idx;
                } else {
                    gin2_1st = gate_values.first.data()
                               + (gin2_idx - input.first.size());
                    gin2_2nd = gate_values.second.data()
                               + (gin2_idx - input.second.size());
                }

                if (0
                    != this->shm3pc_.share_xor(1, gin1_1st, gin1_2nd, gin2_1st,
                                               gin2_2nd, gout_1st, gout_2nd)) {
                    return -1;
                }
            }
                break;
            default:
                return -1;
        }
    }

    return 0;
}

int MPCMCircuit::m_process_AND_gates(const CircuitSpec::gate_list_t & AND_gates,
                                     const RepShrVctr & input, RepShrVctr & gate_values) {
    if (AND_gates.empty()) {
        return 0;
    }

    struct timespec abs_timeout;
    size_t gate_count = AND_gates.size();

    if (gate_in1_.first.size() < gate_count) {
        gate_in1_.first.resize(gate_count);
        gate_in1_.second.resize(gate_count);
        gate_in2_.first.resize(gate_count);
        gate_in2_.second.resize(gate_count);
        gate_out_.first.resize(gate_count);
        gate_out_.second.resize(gate_count);
    }

    size_t gate_offset = 0;
    for (CircuitSpec::gate_list_t::const_iterator i = AND_gates.begin();
         i != AND_gates.end(); ++i) {
        select_gin(gate_in1_.first[gate_offset], gate_in1_.second[gate_offset],
                   i->inp1_, input, gate_values);
        select_gin(gate_in2_.first[gate_offset], gate_in2_.second[gate_offset],
                   i->inp2_, input, gate_values);
        gate_offset++;
    }

    required_trips_ = gate_count;
    if (trip_a_.first.size() < required_trips_) {
        trip_a_.first.resize(required_trips_);
        trip_a_.second.resize(required_trips_);
        trip_b_.first.resize(required_trips_);
        trip_b_.second.resize(required_trips_);
        trip_c_.first.resize(required_trips_);
        trip_c_.second.resize(required_trips_);
    }

//    if (0
//        != shm3pc_.share_and(gate_count, gate_in1_.first.data(),
//                             gate_in1_.second.data(), gate_in2_.first.data(),
//                             gate_in2_.second.data(), gate_out_.first.data(),
//                             gate_out_.second.data())) {
//        cout<<"share and error"<<endl;
//        return -1;
//    }
    sem_post(&get_trips_);

//    if (0
//        != shm3pc_.share_and(gate_count, gate_in1_.first.data(),
//                             gate_in1_.second.data(), gate_in2_.first.data(),
//                             gate_in2_.second.data(), gate_out_.first.data(),
//                             gate_out_.second.data())) {
//        return -1;
//    }

    //wait for got trips
    clock_gettime(CLOCK_REALTIME, &abs_timeout);
    abs_timeout.tv_sec += 3;
    abs_timeout.tv_nsec += 500 * required_trips_;//add 3 sec + 500 ns per triple
    abs_timeout.tv_sec += abs_timeout.tv_nsec / 1000000000;	//move surplus seconds
    abs_timeout.tv_nsec = abs_timeout.tv_nsec % 1000000000;	//clear surplus seconds
    int error = sem_timedwait(&got_trips_, &abs_timeout);

    if (0 == error) {
        if (0
            != shm3pc_.share_and(gate_count, gate_in1_.first.data(),
                                 gate_in1_.second.data(), gate_in2_.first.data(),
                                 gate_in2_.second.data(), gate_out_.first.data(),
                                 gate_out_.second.data())) {
            return -1;
        }

        if (0
            != mhm3pc_.triplet_verification_with_another(gate_count,
                                                         gate_in1_.first.data(), gate_in1_.second.data(),
                                                         gate_in2_.first.data(), gate_in2_.second.data(),
                                                         gate_out_.first.data(), gate_out_.second.data(),
                                                         trip_a_.first.data(), trip_a_.second.data(),
                                                         trip_b_.first.data(), trip_b_.second.data(),
                                                         trip_c_.first.data(), trip_c_.second.data())) {
            return -1;
        }
    } else {
        return -1;
    }

    gate_offset = 0;
    for (CircuitSpec::gate_list_t::const_iterator i = AND_gates.begin();
         i != AND_gates.end(); ++i) {
        size_t output_idx = i->sqnum_ - input.first.size();
        gate_values.first[output_idx] = gate_out_.first[gate_offset];
        gate_values.second[output_idx] = gate_out_.second[gate_offset];
        gate_offset++;
    }

    return 0;
}

int MPCMCircuit::s_process_AND_gates(const CircuitSpec::gate_list_t & AND_gates,
                                     const RepShrVctr & input, RepShrVctr & gate_values) {
    if (AND_gates.empty()) {
        return 0;
    }

    size_t gate_count = AND_gates.size();

    if (gate_in1_.first.size() < gate_count) {
        gate_in1_.first.resize(gate_count);
        gate_in1_.second.resize(gate_count);
        gate_in2_.first.resize(gate_count);
        gate_in2_.second.resize(gate_count);
        gate_out_.first.resize(gate_count);
        gate_out_.second.resize(gate_count);
    }

    size_t gate_offset = 0;
    for (CircuitSpec::gate_list_t::const_iterator i = AND_gates.begin();
         i != AND_gates.end(); ++i) {
        select_gin(gate_in1_.first[gate_offset], gate_in1_.second[gate_offset],
                   i->inp1_, input, gate_values);
        select_gin(gate_in2_.first[gate_offset], gate_in2_.second[gate_offset],
                   i->inp2_, input, gate_values);
        gate_offset++;
    }

    if (0
        != shm3pc_.share_and(gate_count, gate_in1_.first.data(),
                             gate_in1_.second.data(), gate_in2_.first.data(),
                             gate_in2_.second.data(), gate_out_.first.data(),
                             gate_out_.second.data())) {
        return -1;
    }

    gate_offset = 0;
    for (CircuitSpec::gate_list_t::const_iterator i = AND_gates.begin();
         i != AND_gates.end(); ++i) {
        size_t output_idx = i->sqnum_ - input.first.size();
        //TODO expand to more than 1 byte
        gate_values.first[output_idx] = gate_out_.first[gate_offset];
        gate_values.second[output_idx] = gate_out_.second[gate_offset];
        gate_offset++;
    }

    return 0;
}

void MPCMCircuit::select_gin(vu_t & gin1, vu_t & gin2, const size_t gidx,
                             const RepShrVctr & input, const RepShrVctr & gate_values) {
    if (gidx < input.first.size()) {
        gin1 = input.first[gidx];
        gin2 = input.second[gidx];
    } else {
        gin1 = gate_values.first[gidx - input.first.size()];
        gin2 = gate_values.second[gidx - input.first.size()];
    }
}

int MPCMCircuit::m_share_secret(const int pid, const size_t count,
                                const vu_t * v, vu_t* z1, vu_t* z2) {
    return this->mhm3pc_.share_secret(pid, count, v, z1, z2);
}

int MPCMCircuit::m_share_open(const int pid, const size_t count,
                              const vu_t * x1, const vu_t * x2, vu_t * v) {
    return this->mhm3pc_.share_open(pid, count, x1, x2, v);
}

int MPCMCircuit::m_compute(const CircuitSpec & spec, const RepShrVctr & input,
                           RepShrVctr & output) {
    size_t gate_count = spec.get_gate_count();
    size_t input_count = spec.get_input_count();
    if (input.first.size() != input_count) {
        return -1;
    }
    assert(input.first.size() == input.second.size());
    assert(0 != gate_count);

    RepShrVctr gate_values;
    gate_values.first.resize(gate_count);
    gate_values.second.resize(gate_count);

    //size_t layer = 0;

    const CircuitSpec::circuit_gates_t & gates(spec.get_gates());
    for (CircuitSpec::circuit_gates_t::const_iterator i = gates.begin();
         i != gates.end(); ++i) {
        if (0 != process_local_gates(i->first, input, gate_values)) {
            return -1;
        }

        if (0 != m_process_AND_gates(i->second, input, gate_values)) {
            return -1;
        }
    }

    const CircuitSpec::output_sequence_t & output_sequence(
            spec.get_output_sequence());
    output.first.clear();
    output.first.resize(output_sequence.size());
    output.second.clear();
    output.second.resize(output_sequence.size());

    size_t output_offset = 0;
    for (CircuitSpec::output_sequence_t::const_iterator i =
            output_sequence.begin(); i != output_sequence.end(); ++i) {
        if (*i < input_count) {
            output.first[output_offset] = input.first[*i];
            output.second[output_offset] = input.second[*i];
        } else {
            output.first[output_offset] = gate_values.first[*i - input_count];
            output.second[output_offset] = gate_values.second[*i - input_count];
        }
        output_offset++;
    }

    return 0;
}

//int MPCMCircuit::m_Write(const void * data, const size_t data_size, bool us) {
//    return this->mhm3pc_.Write(data, data_size, us);
//}
//
//int MPCMCircuit::m_Read(void * data, const size_t data_size, bool us) {
//    return this->mhm3pc_.Read(data, data_size, us);
//}

int MPCMCircuit::s_share_secret(const int pid, const size_t count,
                                const vu_t * v, vu_t * z1, vu_t * z2) {
    return this->shm3pc_.share_secret(pid, count, v, z1, z2);
}

int MPCMCircuit::s_share_open(const int pid, const size_t count,
                              const vu_t * x1, const vu_t * x2, vu_t * v) {
    return this->shm3pc_.share_open(pid, count, x1, x2, v);
}

int MPCMCircuit::s_share_gen_rand(const size_t count, vu_t * z1, vu_t * z2) {
    return this->shm3pc_.share_gen_rand(count, z1, z2);
}

int MPCMCircuit::s_compute(const CircuitSpec & spec, const RepShrVctr & input,
                           RepShrVctr & output) {
    size_t gate_count = spec.get_gate_count();
    size_t input_count = spec.get_input_count();
    if (input.first.size() != input_count) {
        return -1;
    }
    assert(input.first.size() == input.second.size());
    assert(0 != gate_count);

    gate_values_.first.resize(gate_count);
    gate_values_.second.resize(gate_count);

    //size_t layer = 0;

    const CircuitSpec::circuit_gates_t & gates(spec.get_gates());
    for (CircuitSpec::circuit_gates_t::const_iterator i = gates.begin();
         i != gates.end(); ++i) {
        if (0 != process_local_gates(i->first, input, gate_values_)) {
            return -1;
        }

        if (0 != s_process_AND_gates(i->second, input, gate_values_)) {
            return -1;
        }
    }

    const CircuitSpec::output_sequence_t & output_sequence(
            spec.get_output_sequence());
    output.first.clear();
    output.first.resize(output_sequence.size());
    output.second.clear();
    output.second.resize(output_sequence.size());

    size_t output_offset = 0;
    for (CircuitSpec::output_sequence_t::const_iterator i =
            output_sequence.begin(); i != output_sequence.end(); ++i) {
        if (*i < input_count) {
            output.first[output_offset] = input.first[*i];
            output.second[output_offset] = input.second[*i];
        } else {
            output.first[output_offset] = gate_values_.first[*i - input_count];
            output.second[output_offset] = gate_values_.second[*i - input_count];
        }
        output_offset++;
    }

    return 0;
}

//int MPCMCircuit::s_Write(const void * data, const size_t data_size, bool us) {
//    return this->shm3pc_.Write(data, data_size, us);
//}
//
//int MPCMCircuit::s_Read(void * data, const size_t data_size, bool us) {
//    return this->shm3pc_.Read(data, data_size, us);
//}

int MPCMCircuit::s_scalar_and(const size_t count, const vu_t * x1, const vu_t * x2,
                              const vu_t * s, vu_t * z1, vu_t * z2) {
    return this->shm3pc_.scalar_and(count, x1, x2, s, z1, z2);
}

int MPCMCircuit::s_share_and(const size_t count, const vu_t * x1, const vu_t * x2,
                             const vu_t * y1, const vu_t * y2, vu_t * z1, vu_t * z2) {
    return this->shm3pc_.share_and(count, x1, x2, y1, y2, z1, z2);
}

int MPCMCircuit::s_share_xor(const size_t count, const vu_t * x1, const vu_t * x2,
                             const vu_t * y1, const vu_t * y2, vu_t * z1, vu_t * z2) {
    return this->shm3pc_.share_xor(count, x1, x2, y1, y2, z1, z2);
}

int MPCMCircuit::s_share_shuffle(const size_t count, vector<vu_t> & x1, vector<vu_t> & x2) {
    return this->shm3pc_.share_shuffle(count, x1, x2);
}

int MPCMCircuit::s_share_set_shuffle(const size_t count, vector<vu_t> & x1, vector<vu_t> & x2,
                                     vector<vu_t> & y1, vector<vu_t> & y2, vector<vu_t> & z1, vector<vu_t> & z2) {
    return this->shm3pc_.share_set_shuffle(count, x1, x2, y1, y2, z1, z2);
}
int MPCMCircuit::s_share_set_parity(const size_t count, const vu_t * x1, const vu_t * x2,
                                    const vu_t * y1, const vu_t * y2, const vu_t * z1, const vu_t * z2,
                                    const vu_t * kcol, const vu_t * vcol, const size_t kselect,
                                    vu_t & parity) {
    return this->shm3pc_.share_set_parity(count, x1, x2, y1, y2, z1, z2, kcol,
                                          vcol, kselect, parity);
}

