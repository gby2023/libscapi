#pragma once

#include <vector>
#include <string>
#include <tuple>
#include <fstream>

#include <stdlib.h>
#include <iostream>

using namespace std;
//------------------------------------------------------------------//
class InputSpec {
	/* Input specification file format
	 P0CN		#number of input vector units from party 0
	 P1CN		#number of input vector units from party 1
	 P2CN		#number of input vector units from party 2
	 */
	size_t party_input_count_[3];
public:
	InputSpec();

	size_t get_party_input_count(const int pid) const;
	int set_party_input_count(const int pid, const size_t count);

	int load(const char * input_spec_file);
	int store(const char * input_spec_file) const;
};
//------------------------------------------------------------------//
class Gate {
public:
	typedef enum {
		gt_nil = 0, gt_and, gt_xor, gt_not,
	} type_t;

	Gate();
	Gate(size_t sqnum);
	Gate(const Gate & other);
	Gate(const type_t type, const size_t sqnum, const size_t inp1,
			const size_t inp2);
	~Gate();

	/*
	type_t get_type() const;
	size_t get_sqnum() const;
	size_t get_inp1() const;
	size_t get_inp2() const;
	*/

	int operator <<(std::ifstream &);
	int operator >>(std::ofstream &) const;

	int load_scapi(std::ifstream &);

	bool operator <(const Gate & other) const;
	bool operator >(const Gate & other) const;
	bool operator ==(const Gate & other) const;
	bool operator !=(const Gate & other) const;
	const Gate & operator =(const Gate & other);

    int serialize(int fd) const;
    int deserialize(int fd);
//private:
	type_t type_;
	size_t sqnum_, inp1_, inp2_;
};
//------------------------------------------------------------------//
class CircuitSpec {

	/* Circuit specification file format
	 IVU		#number of input units
	 GN		#number of gates
	 GSN		TYP		INP1	[ INP2 ]
	 ...								#GN lines of gate specs:
	 ...									GSN = Gate Sequence Number; TYP = 'A' for AND / 'X' for XOR / 'N' for NOT;
	 ...									INP1=Input 1 GSN; INP2=Input 2 GSN (N gates have no INP2);
	 GSN		TYP		INP1	[ INP2 ]
	 OUT-GSN, ... OUT-GSN,		#Sequential order of the GSN for output;
	 #The '#' character will be used for comments inside the spec file.
	 */

public:
	CircuitSpec();
	CircuitSpec(const CircuitSpec & other);
	~CircuitSpec();

	typedef vector<Gate> gate_set_t;
	typedef std::vector<Gate> gate_list_t;
	typedef std::pair<gate_list_t,gate_list_t> layer_gates_t;
	typedef std::vector<layer_gates_t> circuit_gates_t;
	typedef std::vector<size_t> output_sequence_t;

	const CircuitSpec & operator = (const CircuitSpec & other);

	size_t get_input_count() const;
	size_t get_gate_count() const;
	const circuit_gates_t & get_gates() const;
	const output_sequence_t & get_output_sequence() const;

	int load(const char * circuit_spec_file);
	int store(const char * circuit_spec_file);

    int serialize(const char * circuit_bin_file) const;
    int deserialize(const char * circuit_bin_file);

//	int load_scapi(const char * circuit_spec_file);
	int load_bristol(const char * circuit_spec_file, const size_t party_count);

	static int vectorize_spec(const size_t vfactor, const CircuitSpec & spec,
			CircuitSpec & vspec);
	static int vectorize_gates(const size_t vfactor,
			const circuit_gates_t & src, circuit_gates_t & dst);
	static int vectorize_output_sequence(const size_t vfactor,
			const output_sequence_t & src, output_sequence_t & dst);
	static int vectorize_layer(const size_t vfactor, const layer_gates_t & src,
			layer_gates_t & dst);
	static int vectorize_list(const size_t vfactor, const gate_list_t & src,
			gate_list_t & dst);
private:
	size_t input_count_, gate_count_;
	circuit_gates_t gates_;
	output_sequence_t output_sequence_;

	int load_input_count(std::ifstream &);
	int load_gates(std::ifstream &);
	int load_output_sequence(std::ifstream &);

    int serialize(int fd) const;
    int deserialize(int fd);

    int serialize_layer(int fd, const layer_gates_t &lyr) const;
    int deserialize_layer(int fd, layer_gates_t &lyr);

	int store_input_count(std::ofstream &);
	int store_gates(std::ofstream &);
	int store_output_sequence(std::ofstream &);

	int sort_gates(gate_set_t & and_gates, gate_set_t & local_gates);
};
//------------------------------------------------------------------//
class OutputSpec {
	//TBD...(output representation)
public:
	OutputSpec();
	~OutputSpec();

	int load(const char * output_spec_file);
	int store(const char * output_spec_file);
};
//------------------------------------------------------------------//
int get_next_number(std::ifstream & csf, u_int64_t & number, int base);

class cdc {
	const size_t vf_, chunks_;
public:
	cdc(const size_t vf, const size_t chunks) :
			vf_(vf), chunks_(chunks) {
	}
	cdc(const cdc & other) :
			vf_(other.vf_), chunks_(other.chunks_) {
	}

	size_t get_vf() const {
		return vf_;
	}
	size_t get_chunks() const {
		return chunks_;
	}

	bool operator <(const cdc & other) const {
		return (this->vf_ * this->chunks_) < (other.vf_ * other.chunks_);
	}
	bool operator ==(const cdc & other) const {
		return (this->vf_ * this->chunks_) == (other.vf_ * other.chunks_);
	}
};