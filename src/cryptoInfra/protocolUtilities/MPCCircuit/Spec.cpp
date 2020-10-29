#include <memory.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/Spec.h"
#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/vectorization_defs.h"

//-----------------------------------------------------------------------------------------------//

InputSpec::InputSpec() {
	memset(party_input_count_, 0, 3 * sizeof(size_t));
}

size_t InputSpec::get_party_input_count(const int pid) const {
	if (-1 < pid && pid < 3)
		return party_input_count_[pid];
	else
		return 0;
}

int InputSpec::set_party_input_count(const int pid, const size_t count) {
	if (-1 < pid && pid < 3) {
		party_input_count_[pid] = count;
		return 0;
	} else
		return -1;
}

int InputSpec::load(const char * input_spec_file) {
	std::ifstream isf(input_spec_file);
	std::string line;

	if (!std::getline(isf, line)) {
		return -1;
	}
	char * p = NULL;
	party_input_count_[0] = (size_t) strtol(line.c_str(), &p, 10);
	if (!p || (const char *) p == line.c_str())
		return -1;

	if (!std::getline(isf, line)) {
		return -1;
	}
	p = NULL;
	party_input_count_[1] = (size_t) strtol(line.c_str(), &p, 10);
	if (!p || (const char *) p == line.c_str())
		return -1;

	if (!std::getline(isf, line)) {
		return -1;
	}
	p = NULL;
	party_input_count_[2] = (size_t) strtol(line.c_str(), &p, 10);
	if (!p || (const char *) p == line.c_str())
		return -1;

	return 0;
}

int InputSpec::store(const char * input_spec_file) const {
	std::ofstream isf(input_spec_file, std::ofstream::out);
	isf << party_input_count_[0] << '\n';
	isf << party_input_count_[1] << '\n';
	isf << party_input_count_[2] << '\n';
	isf.close();
	return 0;
}
//-----------------------------------------------------------------------------------------------//

Gate::Gate() :
		type_(gt_nil), sqnum_(-1), inp1_(-1), inp2_(-1) {
}

Gate::Gate(size_t sqnum) :
		type_(gt_nil), sqnum_(sqnum), inp1_(-1), inp2_(-1) {
}

Gate::Gate(const Gate & other) {
	*this = other;
}

Gate::Gate(const type_t type, const size_t sqnum, const size_t inp1,
		const size_t inp2) :
		type_(type), sqnum_(sqnum), inp1_(inp1), inp2_(inp2) {

}

Gate::~Gate() {
}
/*
Gate::type_t Gate::get_type() const {
	return type_;
}

size_t Gate::get_sqnum() const {
	return sqnum_;
}

size_t Gate::get_inp1() const {
	return inp1_;
}

size_t Gate::get_inp2() const {
	return inp2_;
}
*/
int Gate::operator <<(std::ifstream & csf) {
	std::string line;
	if (!std::getline(csf, line)) {
		return -1;
	}
	std::string::size_type n = line.find_first_of("#\n");
	if (std::string::npos != n)
		line.erase(n);

	n = line.find_first_not_of(" \f\n\r\t\v");
	if (std::string::npos == n)
		return -1;
	if (0 < n)
		line.erase(0, n);

	char * p = NULL;
	sqnum_ = strtol(line.c_str(), &p, 10);
	if (!p || (const char *) p == line.c_str())
		return -1;
	line.erase(0, p - line.c_str());

	n = line.find_first_not_of(" \f\n\r\t\v");
	if (std::string::npos == n)
		return -1;
	if (0 < n)
		line.erase(0, n);

	switch (line[0]) {
	case 'A':
		type_ = gt_and;
		break;
	case 'X':
		type_ = gt_xor;
		break;
	case 'N':
		type_ = gt_not;
		break;
	default:
		return -1;
	}
	line.erase(0, 1);

	n = line.find_first_not_of(" \f\n\r\t\v");
	if (std::string::npos == n)
		return -1;
	if (0 < n)
		line.erase(0, n);

	p = NULL;
	inp1_ = strtol(line.c_str(), &p, 10);
	if (!p || (const char *) p == line.c_str())
		return -1;
	line.erase(0, p - line.c_str());

	if (gt_not != type_) {
		n = line.find_first_not_of(" \f\n\r\t\v");
		if (std::string::npos == n)
			return -1;
		if (0 < n)
			line.erase(0, n);

		p = NULL;
		inp2_ = strtol(line.c_str(), &p, 10);
		if (!p || (const char *) p == line.c_str())
			return -1;
		line.erase(0, p - line.c_str());
	}
	return 0;
}

int Gate::operator >>(std::ofstream & csf) const {

	switch (type_) {
	case gt_and:
		csf << sqnum_ << '\t' << 'A' << '\t' << inp1_ << '\t' << inp2_
				<< std::endl;
		return 0;
	case gt_xor:
		csf << sqnum_ << '\t' << 'X' << '\t' << inp1_ << '\t' << inp2_
				<< std::endl;
		return 0;
	case gt_not:
		csf << sqnum_ << '\t' << 'N' << '\t' << inp1_ << std::endl;
		return 0;
	default:
		return -1;
	}
}

int Gate::load_scapi(std::ifstream & csf) {
	u_int64_t number, input_wires;

	//1. input wire count; should be 1 or 2.
	if(0 != get_next_number(csf, input_wires, 10)) {
		return -1;
	}

	//2. output wire count; must be 1!
	if(0 != get_next_number(csf, number, 10) || 1 != number) {
		return -1;
	}

	//3. read 1 or 2 input wire idxs
	if(0 < input_wires) {
		if(0 != get_next_number(csf, inp1_, 10)) {
			return -1;
		}
		if(1 < input_wires) {
			if(0 != get_next_number(csf, inp2_, 10)) {
				return -1;
			}
		}
	} else {
		return -1;
	}

	//4. the output wire idx is really the gate sq-num.
	if(0 != get_next_number(csf, sqnum_, 10)) {
		return -1;
	}

	//5. the gate truth tbl: '10' for NOT; '0110' for XOR; '0001' for AND;
	if(0 != get_next_number(csf, number, 2)) {
		return -1;
	}
	switch(number) {
	case 1:
		type_ = gt_and;
		if(2 != input_wires) {
			return -1;
		}
		break;
	case 6:
		type_ = gt_xor;
		if(2 != input_wires) {
			return -1;
		}
		break;
	case 2:
		type_ = gt_not;
		if(1 != input_wires) {
			return -1;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

bool Gate::operator <(const Gate & other) const {
	return this->sqnum_ < other.sqnum_;
}

bool Gate::operator >(const Gate & other) const {
	return this->sqnum_ > other.sqnum_;
}

bool Gate::operator ==(const Gate & other) const {
	return this->sqnum_ == other.sqnum_;
}

bool Gate::operator !=(const Gate & other) const {
	return this->sqnum_ != other.sqnum_;
}

const Gate & Gate::operator =(const Gate & other) {
	if (&other != this) {
		this->sqnum_ = other.sqnum_;
		this->type_ = other.type_;
		this->inp1_ = other.inp1_;
		this->inp2_ = other.inp2_;
	}
	return *this;
}

int Gate::serialize(int fd) const {
    ssize_t nio;

    nio = ::write(fd, &type_, sizeof(type_t));
    if (sizeof(type_t) != nio) {
        return -1;
    }

    nio = ::write(fd, &sqnum_, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    nio = ::write(fd, &inp1_, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    if (gt_not != type_) {
        nio = ::write(fd, &inp2_, sizeof(size_t));
        if (sizeof(size_t) != nio) {
            return -1;
        }
    }

    return 0;
}

int Gate::deserialize(int fd) {
    ssize_t nio;

    nio = ::read(fd, &type_, sizeof(type_t));
    if (sizeof(type_t) != nio) {
        return -1;
    }

    nio = ::read(fd, &sqnum_, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    nio = ::read(fd, &inp1_, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    if (gt_not != type_) {
        nio = ::read(fd, &inp2_, sizeof(size_t));
        if (sizeof(size_t) != nio) {
            return -1;
        }
    }

    return 0;
}

//-----------------------------------------------------------------------------------------------//

CircuitSpec::CircuitSpec() :
		input_count_(0), gate_count_(0) {
}

CircuitSpec::CircuitSpec(const CircuitSpec & other) :
		input_count_(other.input_count_), gate_count_(other.gate_count_), gates_(
				other.gates_), output_sequence_(other.output_sequence_) {

}

CircuitSpec::~CircuitSpec() {
}

const CircuitSpec & CircuitSpec::operator = (const CircuitSpec & other) {
	if(this != &other) {
		input_count_ = other.input_count_;
		gate_count_ = other.gate_count_;
		gates_ = other.gates_;
		output_sequence_ = other.output_sequence_;
	}
	return *this;
}

size_t CircuitSpec::get_input_count() const {
	return input_count_;
}

size_t CircuitSpec::get_gate_count() const {
	return gate_count_;
}

const CircuitSpec::circuit_gates_t & CircuitSpec::get_gates() const {
	return gates_;
}

const CircuitSpec::output_sequence_t & CircuitSpec::get_output_sequence() const {
	return output_sequence_;
}

int CircuitSpec::load(const char * circuit_spec_file) {
	int result = -1;
	input_count_ = gate_count_ = 0;
	gates_.clear();
	output_sequence_.clear();
	std::ifstream csf(circuit_spec_file, std::ofstream::in);
	if(csf) {
		if (0 == load_input_count(csf)) {
			if (0 == load_gates(csf)) {
				if (0 == load_output_sequence(csf)) {
					result = 0;
				}
			}
		}
	}
	return result;
}

int CircuitSpec::store(const char * circuit_spec_file) {
	int result = -1;
	std::ofstream csf(circuit_spec_file, std::ofstream::out);
	if(csf) {
		if (0 == store_input_count(csf)) {
			if (0 == store_gates(csf)) {
				if (0 == store_output_sequence(csf)) {
					result = 0;
				}
			}
		}
		csf.close();
	}
	return result;
}

int CircuitSpec::vectorize_spec(const size_t vfactor, const CircuitSpec & spec,
		CircuitSpec & vspec) {
	if (0 != vfactor % (8 * sizeof(vu_t))) {
		return -1;
	}
	size_t vf = (vfactor / (8 * sizeof(vu_t)));
//	cout<<"vf = "<<vf<<endl;
	if (0 == vf) {
		return -1;
	}

	vspec.input_count_ = vf * spec.input_count_;
//	cout<<"vspec.input_count_ = "<<vspec.input_count_<<endl;
	vspec.gate_count_ = vf * spec.gate_count_;
//	cout<<"vspec.gate_count_ = "<<vspec.gate_count_<<endl;
	if (0 != vectorize_gates(vfactor, spec.gates_, vspec.gates_)) {
		return -1;
	}
	if (0
			!= vectorize_output_sequence(vfactor, spec.output_sequence_,
					vspec.output_sequence_)) {
		return -1;
	}
	return 0;
}

int CircuitSpec::vectorize_gates(const size_t vfactor,
			const circuit_gates_t & src, circuit_gates_t & dst) {
	dst.clear();
	for(circuit_gates_t::const_iterator i = src.begin(); i != src.end(); ++i) {
		layer_gates_t lyr;
		if(0 != vectorize_layer(vfactor, *i, lyr)) {
			return -1;
		} else {
			dst.push_back(lyr);
		}
	}
	return 0;
}

int CircuitSpec::vectorize_output_sequence(const size_t vfactor,
		const output_sequence_t & src, output_sequence_t & dst) {
	size_t vf = (vfactor / (8 * sizeof(vu_t)));
	dst.clear();
	for (output_sequence_t::const_iterator i = src.begin(); i != src.end();
			++i) {
		for (size_t k = 0; k < vf; ++k) {
			dst.push_back(*i*vf+k);
		}
	}
	return 0;
}

int CircuitSpec::vectorize_layer(const size_t vfactor,
		const layer_gates_t & src, layer_gates_t & dst) {
	if (0 != vectorize_list(vfactor, src.first, dst.first)) {
		return -1;
	}
	if (0 != vectorize_list(vfactor, src.second, dst.second)) {
		return -1;
	}
	return 0;
}

int CircuitSpec::vectorize_list(const size_t vfactor, const gate_list_t & src,
		gate_list_t & dst) {
	size_t vf = (vfactor / (8 * sizeof(vu_t)));
	dst.clear();
	for (gate_list_t::const_iterator i = src.begin(); i != src.end(); ++i) {
		for (size_t k = 0; k < vf; ++k) {
			Gate g(i->type_, i->sqnum_ * vf + k,
					i->inp1_ * vf + k, i->inp2_ * vf + k);
			dst.push_back(g);
		}
	}
	return 0;
}

int CircuitSpec::load_input_count(std::ifstream & csf) {
	std::string line;
	while (std::getline(csf, line)) {
		std::string::size_type n = line.find_first_of("#\n");
		if (std::string::npos != n)
			line.erase(n);

		n = line.find_first_not_of(" \f\n\r\t\v");
		if (std::string::npos == n) {
			continue;
		}

		if (0 < n) {
			line.erase(0, n);
		}

		char * p = NULL;
		input_count_ = (size_t) strtol(line.c_str(), &p, 10);
		if (!p || (const char *) p == line.c_str()) {
			return -1;
		} else {
			break;
		}
	}
	return 0;
}

int CircuitSpec::store_input_count(std::ofstream & csf) {
	csf << input_count_ << std::endl;
	return 0;
}

int CircuitSpec::load_gates(std::ifstream & csf) {
	std::string line;
	while (std::getline(csf, line)) {
		std::string::size_type n = line.find_first_of("#\n");
		if (std::string::npos != n)
			line.erase(n);

		n = line.find_first_not_of(" \f\n\r\t\v");
		if (std::string::npos == n) {
			continue;
		}

		if (0 < n) {
			line.erase(0, n);
		}

		char * p = NULL;
		gate_count_ = (size_t) strtol(line.c_str(), &p, 10);
		if (!p || (const char *) p == line.c_str()) {
			return -1;
		} else {
			break;
		}
	}

	gate_set_t and_gates, local_gates;
	for (size_t i = 0; i < gate_count_; ++i) {
		Gate gt;
		if (0 != (gt << csf)) {
			return -1;
		}
		if (gt.type_ == Gate::gt_and) {
			and_gates.push_back(gt);
		} else {
			local_gates.push_back(gt);
		}
	}

	if(!and_gates.empty()) {
		if (and_gates.rbegin()->sqnum_ >= (gate_count_ + input_count_)) {
			return -1;
		}
	}

	if(!local_gates.empty()) {
		if (local_gates.rbegin()->sqnum_ >= (gate_count_ + input_count_)) {
			return -1;
		}
	}

	return sort_gates(and_gates, local_gates);
}

int CircuitSpec::sort_gates(gate_set_t & and_gates, gate_set_t & local_gates) {
	gates_.clear();

//	std::set<size_t> assigned_gates_sq;
    vector<bool> isWireReady(gate_count_ + input_count_, false);
    vector<bool> localGateDoneArr(local_gates.size(),false);
    vector<bool> andGateDoneArr(and_gates.size(),false);
    vector<long> newOrderedIndices(gate_count_);
    vector<long> newOrderedIndicesOutputs(gate_count_);

    for(int i=0; i<input_count_; i++){
        isWireReady[i] = true;

    }


    int count = 0;
    int loopCount=0;
    int totalCount = 0;
	while (totalCount<gate_count_) {
		{
			layer_gates_t L;
			gates_.push_back(L);
		}

		int index=0;
//        cout<<"before local loop"<<endl;
		//iterate local gates for a gate of which inputs are circuit inputs or already assigned and assign it
		for (gate_set_t::iterator i = local_gates.begin();
				i != local_gates.end(); index++, i++) {
//		    cout<<"index = "<<index<< " ";
			switch (i->type_) {
			case Gate::gt_not:
//			    cout<<"not gate input0 = "<< i->inp1_<< " ";
//				cout<<"!localGateDoneArr[index]  = "<<!localGateDoneArr[index]<<endl;
//				cout<<"isWireReady[i->inp1_] = "<<isWireReady[i->inp1_]<<endl;
					if (!localGateDoneArr[index] && isWireReady[i->inp1_]) {
//				    cout<<" ready"<<endl;
					//assign and return to start
					gates_.back().first.push_back(*i);
                    isWireReady[i->sqnum_] = true;
                    localGateDoneArr[index] = true;
                    totalCount++;
				}
				break;
			case Gate::gt_xor:
//			    cout<<"xor gate input0 = "<< i->inp1_<< " input1 = "<<i->inp2_<<" ";
				if (!localGateDoneArr[index] && isWireReady[i->inp1_] && isWireReady[i->inp2_]) {
//				    cout<<"ready"<<endl;
					//assign and return to start
					gates_.back().first.push_back(*i);
                    isWireReady[i->sqnum_] = true;
                    localGateDoneArr[index] = true;
					totalCount++;
				}
				break;
			default:
				return -1;
			}
		}

		index = 0;
		loopCount = count;

		//assign the selected and gates
		for (gate_set_t::iterator i = and_gates.begin(); i != and_gates.end(); index++, i++) {
//            cout<<"index = "<<index<<" ";
//            cout<<"and gate. input0 = "<< i->inp1_<< " input1 = "<<i->inp2_<<" ";
			if (!andGateDoneArr[index] && isWireReady[i->inp1_] && isWireReady[i->inp2_]) {
                gates_.back().second.push_back(*i);
                newOrderedIndices[count] = index;
                newOrderedIndicesOutputs[count] = i->sqnum_;
                count++;
                totalCount++;
			}
		}

        for(int i=loopCount; i<count; i++){
            andGateDoneArr[newOrderedIndices[i]] = true;
            isWireReady[newOrderedIndicesOutputs[i]] = true;

        }
	}

	return 0;
}

int CircuitSpec::store_gates(std::ofstream & csf) {
	size_t gate_count = 0;
	for (circuit_gates_t::const_iterator i = gates_.begin(); i != gates_.end();
			++i) {
		gate_count += i->first.size();
		gate_count += i->second.size();
	}
	csf << gate_count << std::endl;
	for (circuit_gates_t::const_iterator i = gates_.begin(); i != gates_.end();
			++i) {
		for (gate_list_t::const_iterator j = i->first.begin();
				j != i->first.end(); ++j) {
			if (0 != (*j >> csf)) {
				return -1;
			}
		}
		for (gate_list_t::const_iterator j = i->second.begin();
				j != i->second.end(); ++j) {
			if (0 != (*j >> csf)) {
				return -1;
			}
		}
	}
	return 0;
}

int CircuitSpec::load_output_sequence(std::ifstream & csf) {
	std::string line;
	while (std::getline(csf, line)) {
		std::string::size_type n = line.find_first_of("#\n");
		if (std::string::npos != n)
			line.erase(n);

		n = line.find_first_not_of(" \f\n\r\t\v");
		if (std::string::npos == n) {
			continue;
		}

		if (0 < n) {
			line.erase(0, n);
		}

		while (!line.empty()) {
			if (!isdigit(line[0])) {
				line.erase(0, 1);
			} else {
				char * p = NULL;
				size_t outp = strtol(line.c_str(), &p, 10);
				if (line.c_str() != p) {
					if(outp >= (input_count_ + gate_count_)) {
						return -1;
					}
					output_sequence_.push_back(outp);
					line.erase(0, p - line.c_str());
				} else {
					return -1;
				}
			}
		}
	}
	return 0;
}

int CircuitSpec::store_output_sequence(std::ofstream & csf) {
	for (output_sequence_t::iterator i = output_sequence_.begin();
			i != output_sequence_.end(); ++i) {
		csf << *i << " ";
	}
	csf << std::endl;
	return 0;
}

int CircuitSpec::serialize(const char * circuit_bin_file) const {
    int result = -1;
    int fd = ::open(circuit_bin_file, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (-1 != fd) {
        result = serialize(fd);
        ::close(fd);
    }
    return result;
}

int CircuitSpec::deserialize(const char * circuit_bin_file) {
    int result = -1;
    int fd = ::open(circuit_bin_file, O_RDONLY);
    if (-1 != fd) {
        result = deserialize(fd);
        ::close(fd);
    }
    return result;
}


int CircuitSpec::serialize(int fd) const {
    ssize_t nio;

    nio = ::write(fd, &input_count_, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    nio = ::write(fd, &gate_count_, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    size_t layers = gates_.size();
    nio = ::write(fd, &layers, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    for (circuit_gates_t::const_iterator i = gates_.begin(); i != gates_.end();
         ++i) {
        if (0 != serialize_layer(fd, *i)) {
            return -1;
        }
    }

    size_t outputs = output_sequence_.size();
    nio = ::write(fd, &outputs, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    for (output_sequence_t::const_iterator j = output_sequence_.begin();
         j != output_sequence_.end(); ++j) {
        nio = ::write(fd, &(*j), sizeof(size_t));
        if (sizeof(size_t) != nio) {
            return -1;
        }
    }

    return 0;
}

int CircuitSpec::deserialize(int fd) {
    ssize_t nio;

    nio = ::read(fd, &input_count_, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    nio = ::read(fd, &gate_count_, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    size_t layers;
    nio = ::read(fd, &layers, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    gates_.clear();
    gates_.resize(layers);

    for (circuit_gates_t::iterator i = gates_.begin(); i != gates_.end(); ++i) {
        if (0 != deserialize_layer(fd, *i)) {
            return -1;
        }
    }

    size_t outputs;
    nio = ::read(fd, &outputs, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    output_sequence_.clear();
    output_sequence_.resize(outputs);

    for (output_sequence_t::iterator j = output_sequence_.begin();
         j != output_sequence_.end(); ++j) {
        nio = ::read(fd, &(*j), sizeof(size_t));
        if (sizeof(size_t) != nio) {
            return -1;
        }
    }

    return 0;
}

int CircuitSpec::serialize_layer(int fd, const layer_gates_t &lyr) const {
    ssize_t nio;
    size_t t;

    t = lyr.first.size();
    nio = ::write(fd, &t, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    for (gate_list_t::const_iterator i = lyr.first.begin();
         i != lyr.first.end(); ++i) {
        if (0 != i->serialize(fd)) {
            return -1;
        }
    }

    t = lyr.second.size();
    nio = ::write(fd, &t, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    for (gate_list_t::const_iterator i = lyr.second.begin();
         i != lyr.second.end(); ++i) {
        if (0 != i->serialize(fd)) {
            return -1;
        }
    }

    return 0;
}

int CircuitSpec::deserialize_layer(int fd, layer_gates_t &lyr) {
    ssize_t nio;
    size_t t;

    nio = ::read(fd, &t, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    lyr.first.clear();
    lyr.first.resize(t);

    for (gate_list_t::iterator i = lyr.first.begin(); i != lyr.first.end();
         ++i) {
        if (0 != i->deserialize(fd)) {
            return -1;
        }
    }

    nio = ::read(fd, &t, sizeof(size_t));
    if (sizeof(size_t) != nio) {
        return -1;
    }

    lyr.second.clear();
    lyr.second.resize(t);

    for (gate_list_t::iterator i = lyr.second.begin(); i != lyr.second.end();
         ++i) {
        if (0 != i->deserialize(fd)) {
            return -1;
        }
    }

    return 0;
}
//
//int CircuitSpec::load_scapi(const char * circuit_spec_file) {
//
//	std::ifstream csf(circuit_spec_file);
//	u_int64_t number;
//
//	//read the gate count
//	size_t gate_count;
//	if (0 != get_next_number(csf, number, 10)) {
//		return -1;
//	}
//	gate_count = number;
//
//	//read the party count
//	size_t party_count;
//	if (0 != get_next_number(csf, number, 10)) {
//		return -1;
//	}
//	party_count = number;
//
//	//*********************************************** INPUTS
//	//declare the party input offset maps
//	size_t overall_input_count = 0;
//	std::set<u_int64_t> input_idx;
//
//	//inputs: for each party
//	for (size_t i = 0; i < party_count; ++i) {
//		if (0 != get_next_number(csf, number, 10)) {
//			return -1;
//		}
//		//party-id D/C
//
//		size_t party_input_count;
//		if (0 != get_next_number(csf, number, 10)) {
//			return -1;
//		}
//		party_input_count = number;
//
//		if (0 < party_input_count) {
//			for (size_t j = 0; j < party_input_count; ++j) {
//				if (0 != get_next_number(csf, number, 10)) {
//					return -1;
//				}
//
//				//check for duplicate input indexes
//				if (!input_idx.insert(number).second) {
//					return -1;
//				}
//			}
//		}
//
//		//add this party input count to the total
//		overall_input_count += party_input_count;
//	}
//
//	//check for input index out of sequence
//	if (!input_idx.empty() && *input_idx.rbegin() >= overall_input_count) {
//		return -1;
//	}
//	input_idx.clear();
//
//	//*********************************************** OUTPUTS
//	//declare the party output offset maps
//	output_sequence_t party_outputs;
//	//outputs: for each party
//	for (size_t i = 0; i < party_count; ++i) {
//		if (0 != get_next_number(csf, number, 10)) {
//			return -1;
//		}
//		//party-id D/C
//
//		size_t party_output_count;
//		if (0 != get_next_number(csf, number, 10)) {
//			return -1;
//		}
//		party_output_count = number;
//
//		if (0 < party_output_count) {
//			for (size_t j = 0; j < party_output_count; ++j) {
//				if (0 != get_next_number(csf, number, 10)) {
//					return -1;
//				}
//
//				//output index out of range
//				if ((overall_input_count + gate_count) <= number) {
//					return -1;
//				}
//				party_outputs.push_back(number);
//			}
//		}
//	}
//
//	//*********************************************** GATES
//	gate_set_t and_gates, local_gates;
//	Gate gt;
//	//for each gate
//	for (size_t i = 0; i < gate_count; ++i) {
//		if (0 != gt.load_scapi(csf)) {
//			return -1;
//		}
//
//		if (gt.type_ == Gate::gt_and) {
//			and_gates.insert(gt));
//		} else {
//			local_gates.insert(gt);
//		}
//	}
//
//	//*********************************************** LOAD
//	input_count_ = overall_input_count;
//
//	if (0 != sort_gates(and_gates, local_gates)) {
//		return -1;
//	}
//
//	output_sequence_.swap(party_outputs);
//
//	return 0;
//}

int CircuitSpec::load_bristol(const char * circuit_spec_file, const size_t party_count) {
	std::ifstream csf(circuit_spec_file);
	//u_int64_t number;
	//TODO: To be implemented in the future!
	return -1;
}

//-----------------------------------------------------------------------------------------------//

int get_next_number(std::ifstream & csf, u_int64_t & number, int base) {
	int result = -1;
	std::string str;
	if (csf >> str) {
		char * p = NULL;
		number = (u_int64_t) strtol(str.c_str(), &p, base);
		if (str.c_str() != p) {
			result = 0;
		}
	}
	return result;
}