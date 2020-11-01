//
// Created by moriya on 10/27/20.
//

#ifndef SCAPI_UTILITIES3PARTIES_H
#define SCAPI_UTILITIES3PARTIES_H

#include "../../comm/MPCCommunication.hpp"
#include "../../cryptoInfra/Protocol.hpp"
#include "../../infra/Measurement.hpp"
#include "../../cryptoInfra/Key.hpp"
#include "../../primitives/Prg.hpp"
#include "MPCCircuit/MPCMCircuitV.h"
#include "MPCCircuit/circuit_thread.h"
#include <set>

#define flag_print_timings true


typedef struct {
    size_t low; //!< low index of the part
    size_t high; //!< high index of the part
} quicksort_part;


typedef std::map<size_t, CircuitSpec> CircMap;

class Utilities3Parties {
private:
    int partyID;
    int numElements;                    //Number of nodes and edges
    int numThreads;
    bool malicious;

    shared_ptr<CommParty> nextChannel;  //The channel that connect me to the next party - (myId + 1) % 3
    shared_ptr<CommParty> prevChannel;  //The channel that connect me to the previous party - (myId - 1) % 3
    vector<shared_ptr<CommParty>> threadsNextChannels;
    vector<shared_ptr<CommParty>> threadsPrevChannels;

    PrgFromOpenSSLAES* prg;              //PRG to use when random bits are needed
    PrgFromOpenSSLAES* nextPrg;          //Common PRG between me and the next party
    PrgFromOpenSSLAES* prevPrg;          //Common PRG between me and the previous party

    MPCMCircuitV * circuit; // vectorized (malicious secure) circuit object
    CircMap comps_; // map for comparator circuits (mapping size into circuit specification)
    size_t minvf_, maxvf_; //minimal/maximal vectorization factors
    vector<circuit_thread*> workers_; //!< workers vector
    std::set<cdc> scale_;

    vector<int> nextPermutation;                //Used in order to do the reverse shuffle
    vector<int> prevPermutation;                //Used in order to do the reverse shuffle

    vector<int> nextFinalPermutation;
    vector<int> nextFinalReversePermutation;
    vector<int> prevFinalPermutation;
    vector<int> prevFinalReversePermutation;

    ofstream outputFile;

    //In the shuffle algorithm, there are 3 phases. In each phase there is a role for each one of the parties.
    //The roles are implemented in the three follow functions:
    //The reverse parameter indicates whether to compute the regular shuffle or the reverse shuffle.
    // The code is very similar so we implement that in the same function.
    int share_shuffle_upstream(vector<vector<byte>*> & input, int numElements, bool reverse);
    int share_shuffle_downstream(vector<vector<byte>*> & input, int numElements, bool reverse);
    int share_shuffle_passive(vector<vector<byte>*> & input, int numElements);

    void computeShuffleFinalPermutation(vector<int> & shufflePermutation,
                                        vector<int> & shuffleFinalPermutation,
                                        vector<int> & shuffleFinalReversePermutation,
                                        PrgFromOpenSSLAES* prg);

    //Swap the elements in the vector according to the given shuffle permutation
    void computeShufflePermutation(vector<int> & shuffleFinalPermutation,vector<vector<byte>> & input);
    int workers_shufflePermutation(vector<int> & shuffleFinalPermutation, vector<vector<byte>*> & input);

    bool checkSort(byte* recBufs, int numBytes, int elementSize);
    void printOpenedSharesArr(byte* recBufs, int numBytes, int elementSize, ofstream* output);

    //The follow functions are part of the sort algorithm:

    //Gets parts of the vector and sort each part separately
    bool partition(vector<vector<byte>*> & input, vector<byte> & sortParamFirst, vector<byte> & sortParamSecond, vector<quicksort_part> &parts, vector<quicksort_part> &nparts,
                   pair<vector<byte>, vector<byte>> &part_input, pair<vector<byte>, vector<byte>> &part_output,
                   vector<byte> &part_compRes, bool malicious, bool sortWithID, int elementSize);
    //Use the compare circuit in order to sort the input vector
    int inline_circuit(int count, int inputSize, int outputSize, pair<vector<byte>, vector<byte>> &input, pair<vector<byte>,
    vector<byte>> &output, vector<byte> &compRes, bool malicious, CircMap & cSpec, bool toOpen);

    int workers_circuit(int count, int inputBytes, int outputBytes, pair<vector<byte>, vector<byte>> &input,
                        pair<vector<byte>, vector<byte>> &output, bool malicious, CircMap & circuit);

    int workers_compare(int count, int inputSize, int outputSize, pair<vector<byte>, vector<byte>> &input,
                        pair<vector<byte>, vector<byte>> &output, vector<byte> &compRes, bool malicious, CircMap & cSpec, bool toOpen);
    void select_cdc(size_t count, size_t & chunks, size_t & vf);
    // After the compare circuit is called and there are results, this function swaps the elements in all the shares
    // vectors according to the compare results.
    void inline_swap(vector<vector<byte>*> & input, vector<quicksort_part> & parts, vector<quicksort_part> & nparts, vector<byte> & compRes, bool sortWithID, int elementSize);
    void workers_swap(vector<vector<byte>*> & input, vector<quicksort_part> &parts, vector<quicksort_part> &nparts, vector<byte> &compRes, bool sortWithID);
    //Swap two shares in the shares vectors.
    void sharesSwap(vector<vector<byte>*> & input, int lIndex, int rIndex, bool sortWithID);
    //Gets a specific shares and swap the elements
    void swapElement(vector<byte> & v, int lIndex, int rIndex, int elementSize);

    //loads the underlying compare circuits
    bool load_compare_circuits(const char * comp_deep_circuit, const char * comp_shallow_circuit);
    bool load_circuits_helper(const char * circuit, size_t vf_start, size_t vf_stop, CircMap & comps);
    bool loadCircuitFromFile(CircuitSpec & csplain, const char * txtName,  const char * binName, bool toSerialize);

//    int start_workers(size_t workers_count, vector<shared_ptr<CommParty>> & threadsNextChannels, vector<shared_ptr<CommParty>> & threadsPrevChannels);
//    void stop_workers();
    int init_scale();


    //Copy each share to the right place according to the mapping SH32
    void permuteVector(vector<byte> & vToPermute, int numElements, int elementSize, vector<int> & mapping);

//    void createThreadFiles(string partiesFile);

public:

    Utilities3Parties(int partID, shared_ptr<CommParty> & nextChannel, shared_ptr<CommParty> & prevChannel,
                      int numThreads, int numElements, PrgFromOpenSSLAES* prg,
                      PrgFromOpenSSLAES* nextPrg, PrgFromOpenSSLAES* prevPrg, bool malicious, string partiesFile,
                      vector<shared_ptr<CommParty>> & threadsNextChannels,
                      vector<shared_ptr<CommParty>> & threadsPrevChannels, vector<circuit_thread*> & workers);
    ~Utilities3Parties();

    //Compute the shuffle algorithm
    int shuffle(vector<vector<byte>*> & input, int numElements);
    //Compute the reverse shuffle algorithm
    int shuffleBack(vector<vector<byte>*> & input, int numElements);

    //Open the shares.
    //Each party send the first share to both other parties and does xor between his value and the other two values.
    //This open function is for xor-shares case.
    int open(pair<vector<byte>,vector<byte>> sendBufs,  byte* recBufs, int numBytes);
    //This function is for the additive shares case. The open is done using operations in Mersenne field, which is different
    // from the other open function that use xor operation.
//    void openMersenne(ZpMersenneIntElement* sendBufs, ZpMersenneIntElement* recBufs, int numElements);

    //Compute the sort algorithm
    int sort(vector<vector<byte>*> & input, size_t numElements, vector<byte> & sortParamFirst, vector<byte> & sortParamSecond, bool malicious, bool sortWithID);

    void permute(vector<vector<byte>*> & input, int numElements, vector<int> & mapping);
    //The next functions are the protocol flow:
    void workers_permute(vector<vector<byte>*> & input, int numElements, vector<int> & mapping);
};

#endif //SCAPI_UTILITIES3PARTIES_H