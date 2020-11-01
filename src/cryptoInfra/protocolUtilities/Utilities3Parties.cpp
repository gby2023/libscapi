//
// Created by moriya on 10/27/20.
//

#include "../../../include/cryptoInfra/protocolUtilities/Utilities3Parties.hpp"
#include <thread>

static constexpr size_t g_comparison_circuit_threshold = (1 << 17);

Utilities3Parties::Utilities3Parties(int partyID, shared_ptr<CommParty> & nextChannel, shared_ptr<CommParty> & prevChannel,
                                     int numThreads, int numElements, PrgFromOpenSSLAES* prg,
                                     PrgFromOpenSSLAES* nextPrg, PrgFromOpenSSLAES* prevPrg, bool malicious,
                                     string partiesFile, vector<shared_ptr<CommParty>> & threadsNextChannels,
                                     vector<shared_ptr<CommParty>> & threadsPrevChannels, vector<circuit_thread*> & workers)
                 : partyID(partyID), nextChannel(nextChannel), prevChannel(prevChannel), numThreads(numThreads), numElements(numElements),
                 prg(prg), nextPrg(nextPrg), prevPrg(prevPrg), malicious(malicious), threadsNextChannels(threadsNextChannels),
                 threadsPrevChannels(threadsPrevChannels), workers_(workers) {

    auto t1 = high_resolution_clock::now();

    computeShuffleFinalPermutation(prevPermutation,
                                   prevFinalPermutation,
                                   prevFinalReversePermutation,
                                   prevPrg);

    computeShuffleFinalPermutation(nextPermutation,
                                   nextFinalPermutation,
                                   nextFinalReversePermutation,
                                   nextPrg);

    auto t2 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds for computing permutations: " << duration << endl;
    }


    //Initialise the compare circuit with 32 bit elements
    circuit = new MPCMCircuitV(partyID, nextChannel, prevChannel, prg, prevPrg, nextPrg);
    circuit->Init();

    minvf_ = 32;
    maxvf_ = 2097152;
    if (numElements > maxvf_){
        maxvf_ = 16777216;
    }

    if (!load_compare_circuits("../libscapi/assets/circuits/boolean/compare/comparator_le_1_32.circuit", "../libscapi/assets/circuits/boolean/compare/shallow_comparator_le_1_32.circuit")) {
        cout<<"comparison circuit load failure."<<endl;
        exit(-1);
    }

    if (workers_.size() > 0 && 0 != init_scale()) {
        cout<<"division scale initialization failure."<<endl;
    }

    string tmp = "init times";
    //cout<<"before sending any data"<<endl;
    vector<byte> tmpBytes(tmp.size());
    nextChannel->write(tmp);
    prevChannel->write(tmp);
    nextChannel->read(tmpBytes.data(), tmp.size());
    prevChannel->read(tmpBytes.data(), tmp.size());

}

int Utilities3Parties::open(pair<vector<byte>,vector<byte>> sendBufs, byte* recBufs, int numBytes){


    const byte* x1_head = sendBufs.first.data();
    const byte* x2_head = sendBufs.second.data();
    byte* v_head = recBufs;
    size_t due = numBytes, done = 0, inc;
    while (done < due) {
        inc = due - done;
        if (inc > 65536) {
            inc = 65536;
        }
        nextChannel->write(x1_head, inc);
        prevChannel->write(x2_head, inc);


        vector<byte> x1_ds(inc), x2_us(inc);
//		cout<<"read from prev"<<endl;
        prevChannel->read(x1_ds.data(), inc);
        nextChannel->read(x2_us.data(), inc);

        if (0 != memcmp(x1_ds.data(), x2_us.data(), inc)) {
            return -1;
        }
        const byte * x3 = x1_ds.data();
#pragma GCC ivdep
        for (size_t i = 0; i < inc; ++i) {
            v_head[i] = x1_head[i] ^ x2_head[i] ^ x3[i];
        }

//        if (0 != share_open_unthrottled(pid, inc, x1_head, x2_head, v_head)) {
//            return -1;
//        }
        done += inc;
        x1_head += inc;
        x2_head += inc;
        v_head += inc;
    }
}

void Utilities3Parties::printOpenedSharesArr(byte* recBufs, int numBytes, int elementSize, ofstream* output) {

    for (int i=0;i<numBytes; i+=elementSize){

        uint32_t tmp = recBufs[i+elementSize - 1];
        for (int j=elementSize-2; j>=0; j--){
            tmp <<= 8;
            tmp |= recBufs[i+j];
        }
        if (output == nullptr){
            cout<<tmp<<" ";
        } else {
            (*output) << tmp << " ";
        }
    }
    if (output == nullptr) {
        cout << endl;
    } else {
        (*output) << endl;
    }
}

Utilities3Parties::~Utilities3Parties(){

}


bool Utilities3Parties::checkSort(byte* recBufs, int numBytes, int elementSize){
    bool sorted = true;
    uint32_t prev = 0;
    for (int i=0; i<numBytes; i+=elementSize){

        uint32_t curr = recBufs[i+elementSize - 1];
        for (int j=elementSize-2; j>=0; j--){
            curr <<= 8;
            curr |= recBufs[i+j];
        }
        if (prev > curr){
            sorted = false;
            break;
        } else if (prev < curr){
            prev = curr;
        }

    }

    return sorted;
}

void Utilities3Parties::permute(vector<vector<byte>*>& input, int numElements, vector<int> & mapping){

    //permute each vector of src/dest/val/bit shares using the mappingIds mapping vector
    for (int i=0; i<input.size(); i++) {
        permuteVector(*input[i], numElements, input[i]->size() / numElements, mapping);
    }

}

void Utilities3Parties::permuteVector(vector<byte> & vToPermute, int numElements, int elementSize, vector<int> & mapping){

    //copy the original vector because the swap will override the data
    vector<byte> tmp(numElements*elementSize);

    //copy each share to the right location according to the mappingIds mapping vector
    for (int i=0; i<numElements; i++) {

        memcpy(tmp.data() + i * elementSize, vToPermute.data() + mapping[i] * elementSize, elementSize);
    }

    vToPermute = move(tmp);
}

void Utilities3Parties::workers_permute(vector<vector<byte>*>& input, int numElements, vector<int> & mapping){

    workers_shufflePermutation(mapping, input);

}

int Utilities3Parties::shuffle(vector<vector<byte>*>& input, int numElements) {
    //The shuffle algorithm contains 3 phases.
    //In each phase there is a role for each one of the parties - upstream, downstream and passive.
    switch (partyID) {
        case 0:
            //Party 0 executes the downstream, then the passive and in the end the upstream role.
            if (0 != share_shuffle_downstream(input, numElements, false)) {
                cout<<"share_shuffle_downstream error"<<endl;
                return -1;
            }

            if (0 != share_shuffle_passive(input, numElements)) {
                cout<<"share_shuffle_passive error"<<endl;
                return -1;
            }
            if (0 != share_shuffle_upstream(input, numElements, false)) {
                cout<<"share_shuffle_upstream error"<<endl;
                return -1;
            }

            break;
        case 1:
            //Party 1 executes the upstream, then the downstream and in the end the passive role.
            if (0 != share_shuffle_upstream(input, numElements, false)) {
                cout<<"share_shuffle_upstream error"<<endl;
                return -1;
            }

            if (0 != share_shuffle_downstream(input, numElements, false)) {
                cout<<"share_shuffle_downstream error"<<endl;
                return -1;
            }

            if (0 != share_shuffle_passive(input, numElements)) {
                cout<<"share_shuffle_passive error"<<endl;
                return -1;
            }

            break;
        case 2:
            //Party 2 executes the passive, then the upstream and in the end the downstream role.
            if (0 != share_shuffle_passive(input, numElements)) {
                cout<<"share_shuffle_passive error"<<endl;
                return -1;
            }

            if (0 != share_shuffle_upstream(input, numElements, false)) {
                cout<<"share_shuffle_upstream error"<<endl;
                return -1;
            }

            if (0 != share_shuffle_downstream(input, numElements, false)) {
                cout<<"share_shuffle_downstream error"<<endl;
                return -1;
            }
            break;
        default:
            return -1;
    }

    return 0;
}

int Utilities3Parties::share_shuffle_upstream(vector<vector<byte>*>& input, int numElements, bool reverse) {
    //Nomenclature per upstream party as P1 (S2)
    vector<vector<byte>> inputTag(input.size());
    vector<vector<byte>*> inputTagP(input.size());
    for (int i=0 ;i<input.size(); i++){
        inputTag[i] = *input[i];
        inputTagP[i] = &inputTag[i];
    }

    auto t1 = high_resolution_clock::now();

    if (!reverse){
        if (workers_.size() == 0) {
            computeShufflePermutation(prevFinalPermutation, inputTag);
        } else {
            workers_shufflePermutation(prevFinalPermutation, inputTagP);
        }
    } else {
        if (workers_.size() == 0) {
            computeShufflePermutation(prevFinalReversePermutation, inputTag);
        } else {
            workers_shufflePermutation(prevFinalReversePermutation, inputTagP);
        }
    }

    auto t2 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds for shuffle upstream permutation or reverse: " << duration << endl;
        outputFile << "time in milliseconds for shuffle upstream permutation or reverse: " << duration << endl;
    }


    t1 = high_resolution_clock::now();

    //Get new random shares from the common PRG
    for (int i=1; i<input.size(); i+=2){
        nextPrg->getPRGBytes(*input[i], 0, input[i]->size());
    }
    vector<vector<byte>> inputTagXorInput(input.size());
    for (int j=0; j<input.size(); j++) {
        inputTagXorInput[j].resize(input[j]->size());
    }

    for (int j=0; j<input.size(); j+=2) {
        //Xor the random shares with the permuted shares
#pragma GCC ivdep
        for (size_t i = 0; i < input[j]->size(); ++i) {
            inputTagXorInput[j][i] = inputTag[j+1][i] ^ (*input[j + 1])[i];

        }
    }

    size_t due, done, inc;

    for (int j=0; j<input.size(); j+=2) {
        due = inputTagXorInput[j].size();
        done = 0;

        const byte * srcwhead = inputTagXorInput[j].data();
        byte * srcrhead = inputTagXorInput[j + 1].data();

        while (done < due) {
            inc = due - done;
            if (inc > 65536) {
                inc = 65536;
            }


            prevChannel->write(srcwhead, inc);
            prevChannel->read(srcrhead, inc);

            srcwhead += inc;
            srcrhead += inc;

            done += inc;
        }
    }

    //Xor all together = π(B) ⊕ (π(A) ⊕ AO ) ⊕ (π(C) ⊕ CO )
    for (int j=0; j<input.size(); j+=2) {

#pragma GCC ivdep
        for (size_t i = 0; i < input[j]->size(); ++i) {
            (*input[j])[i] = inputTag[j][i] ^ inputTagXorInput[j + 1][i] ^ inputTagXorInput[j][i];
        }
    }

    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds for shuffle upstream rest: " << duration << endl;
        outputFile << "time in milliseconds for shuffle upstream rest: " << duration << endl;
    }
    return 0;
}
void Utilities3Parties::computeShuffleFinalPermutation(vector<int> & shufflePermutation,
                                                   vector<int> & shuffleFinalPermutation,
                                                   vector<int> & shuffleFinalReversePermutation,
                                                   PrgFromOpenSSLAES* prg){

    if (shufflePermutation.size() == 0) { //this is the first time shuffle is called so get a random permutation
        shufflePermutation.resize(numElements - 1);
        shuffleFinalPermutation.resize(numElements);
        shuffleFinalReversePermutation.resize(numElements);


        vector<uint64_t> permutation(numElements - 1);
        prg->getPRGBytes((byte*)permutation.data(), (numElements - 1)*sizeof(uint64_t));
        for (size_t i = 0; i < numElements - 1; ++i) {
            size_t j = i + (permutation[i] % (numElements - i));

            shufflePermutation[i] = j;
        }
        for (size_t i = 0; i < numElements ; ++i) {
            shuffleFinalPermutation[i] = i;
            shuffleFinalReversePermutation[i] = i;

        }

        //now calc the final permutations
        for (size_t i = 0; i < numElements - 1; ++i) {
            size_t j = shufflePermutation[i];
            if (i == j) {
                continue;
            }

            swap(shuffleFinalPermutation[i], shuffleFinalPermutation[j]);
        }

        //now calc the final reverse permutations
        for (int i = numElements-2; i >= 0; i--) {
            size_t j = shufflePermutation[i];
            if (i == j) {
                continue;
            }

            swap(shuffleFinalReversePermutation[i], shuffleFinalReversePermutation[j]);
        }
    }
}
void Utilities3Parties::computeShufflePermutation(vector<int> & shuffleFinalPermutation, vector<vector<byte>> & input) {

    vector<vector<byte>> inputTemp(input.size());
    for (int j = 0; j<input.size(); j++) {
        inputTemp[j].resize(input[j].size());
        int elementSize = input[j].size()/numElements;

        //go over the permutation and get the relevan alue accordingly
        for (size_t i = 0; i < numElements; ++i) {
            //Save the element in the left index in a temp array
            memcpy(inputTemp[j].data() + i * elementSize, input[j].data() + shuffleFinalPermutation[i] * elementSize, elementSize);
        }

        //move back from the temp arrays to the original arrays
        input[j] = move(inputTemp[j]);

    }

}

int Utilities3Parties::workers_shufflePermutation(vector<int> & shuffleFinalPermutation, vector<vector<byte>*> & input) {

    auto t1 = high_resolution_clock::now();
    circuit_thread::ct_task_t task;
    size_t cid = 0;

    vector<vector<byte>> sharesTemp(input.size());
    for (int i=0; i<input.size(); i++){
        sharesTemp[i].resize(input[i]->size());
    }

    int sizeForEachThread;
    if (numElements <= numThreads){
        numThreads = numElements;
        sizeForEachThread = 1;
    } else{
        sizeForEachThread = (numElements + numThreads - 1)/ numThreads;
    }

    for (size_t c = 0; c < numThreads; c++) {

        task.tid = c;
        task.ct_type = circuit_thread::ct_task_t::ct_shuffle;
        task.u.shuffle.sharesPointers = &input;
        task.u.shuffle.sharesTemp = &sharesTemp;
        task.u.shuffle.shuffleFinalPermutation = shuffleFinalPermutation.data();
        task.u.shuffle.start = c*sizeForEachThread;
        if ((c + 1) * sizeForEachThread <= numElements) {
            task.u.shuffle.end = (c + 1) * sizeForEachThread;
        } else {
            task.u.shuffle.end = numElements;
        }
        task.u.shuffle.numElements = numElements;

        cid = c % workers_.size();
        if (0 != workers_[cid]->iq_.push(task)) {
            cout<<"circuiter["<<cid<<"].iq_.push() failure."<<endl;
            return -1;
        }
    }
    auto t2 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds for prepare threads: " << duration << endl;
    }

    t1 = high_resolution_clock::now();
    for (size_t c = 0; c < numThreads; c++) {
        cid = c % workers_.size();
        if (0 != workers_[cid]->oq_.pop(task)) {
            cout<<"circuiter["<<cid<<"].oq_.pop() failure."<<endl;
            return -1;
        }
    }

    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds for finish threads: " << duration << endl;
    }

    t1 = high_resolution_clock::now();
    for (int i=0; i<input.size(); i++){
        *input[i] = move(sharesTemp[i]);
    }

    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds for move: " << duration << endl;
    }
    return 0;
}

int Utilities3Parties::share_shuffle_downstream(vector<vector<byte>*> & input, int numElements, bool reverse) {
    //Nomenclature per downstream party = P0 (S1)
    vector<vector<byte>> inputTag(input.size());
    vector<vector<byte>*> inputTagP(input.size());
    for (int i=0 ;i<input.size(); i++){
        inputTag[i] = *input[i];
        inputTagP[i] = &inputTag[i];
    }

    auto t1 = high_resolution_clock::now();

    if (!reverse){
        if (workers_.size() == 0) {
            computeShufflePermutation(nextFinalPermutation, inputTag);
        } else {
            workers_shufflePermutation(nextFinalPermutation, inputTagP);
        }
    } else {
        if (workers_.size() == 0) {
            computeShufflePermutation(nextFinalReversePermutation, inputTag);
        } else {
            workers_shufflePermutation(nextFinalReversePermutation, inputTagP);
        }
    }

    auto t2 = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds for shuffle downstream permutation or reverse: " << duration << endl;
        outputFile << "time in milliseconds for shuffle downstream permutation or reverse: " << duration << endl;
    }

    t1 = high_resolution_clock::now();

    //Get new random shares from the common PRG
    for (int i=0; i<input.size(); i+=2){
        prevPrg->getPRGBytes(*input[i], 0, input[i]->size());
    }

    vector<vector<byte>> inputTagXorInput(input.size());
    for (int j=0; j<input.size(); j++) {
        inputTagXorInput[j].resize(input[j]->size());
    }

    //Xor the random shares with the permuted shares
    for (int j=0; j<input.size(); j+=2) {
        //Xor the random shares with the permuted shares
#pragma GCC ivdep
        for (size_t i = 0; i < input[j]->size(); ++i) {
            inputTagXorInput[j][i] = inputTag[j][i] ^ (*input[j])[i];

        }
    }

    size_t due, done, inc;

    for (int j=0; j<input.size(); j+=2) {
        due = inputTagXorInput[j].size();
        done = 0;

        const byte *srcwhead = inputTagXorInput[j].data();
        byte *srcrhead = inputTagXorInput[j + 1].data();

        //send the Xor result to the other party
        //And get his xor result
        while (done < due) {
            inc = due - done;
            if (inc > 65536) {
                inc = 65536;
            }

            nextChannel->write(srcwhead, inc);
            nextChannel->read(srcrhead, inc);

            srcwhead += inc;
            srcrhead += inc;

            done += inc;
        }
    }

    //Xor all together = π(B) ⊕ (π(A) ⊕ AO ) ⊕ (π(C) ⊕ CO )
    for (int j=0; j<input.size(); j+=2) {

#pragma GCC ivdep
        for (size_t i = 0; i < input[j]->size(); ++i) {
            (*input[j + 1])[i] = inputTag[j+1][i] ^ inputTagXorInput[j + 1][i] ^ inputTagXorInput[j][i];
        }
    }

    t2 = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(t2-t1).count();
    if(flag_print_timings) {
        cout << "time in milliseconds for shuffle downstreem rest : " << duration << endl;
        outputFile << "time in milliseconds for shuffle downstreem rest : " << duration << endl;
    }

    return 0;
}

int Utilities3Parties::share_shuffle_passive(vector<vector<byte>*> & input, int numElements) {
    //Nomenclature per passive party = P2 (S3)
    for (int i=0; i<input.size(); i+=2){
        prevPrg->getPRGBytes(*input[i], 0, input[i]->size());
        nextPrg->getPRGBytes(*input[i+1], 0, input[i+1]->size());
    }

    return 0;
}

int Utilities3Parties::shuffleBack(vector<vector<byte>*> & input, int numElements) {
    //The reverse shuffle algorithm contains 3 phases.
    //In each phase there is a role for each one of the parties - upstream, downstream and passive.
    //In order to reverse the shuffle, the order of the phases is the opposite of the shuffle algorithm.
    switch (partyID) {
        case 0:
            //Party 0 executes the upstream, then the passive and in the end the downstream role.
            if (0 != share_shuffle_upstream(input, numElements, true)) {
                cout<<"share_shuffle_upstream error"<<endl;
                return -1;
            }

            if (0 != share_shuffle_passive(input, numElements)) {
                cout<<"share_shuffle_passive error"<<endl;
                return -1;
            }

            if (0 != share_shuffle_downstream(input, numElements, true)) {
                cout<<"share_shuffle_downstream error"<<endl;
                return -1;
            }

            break;
        case 1:
            //Party 1 executes the passive, then the downstream, and in the end the upstream role.
            if (0 != share_shuffle_passive(input, numElements)) {
                cout<<"share_shuffle_passive error"<<endl;
                return -1;
            }
            if (0 != share_shuffle_downstream(input, numElements,  true)) {
                cout<<"share_shuffle_downstream error"<<endl;
                return -1;
            }
            if (0 != share_shuffle_upstream(input, numElements, true)) {
                cout<<"share_shuffle_upstream error"<<endl;
                return -1;
            }
            break;
        case 2:
            //Party 2 executes the downstream, then the upstream, and in the end the passive role.
            if (0 != share_shuffle_downstream(input, numElements, true)) {
                cout<<"share_shuffle_downstream error"<<endl;
                return -1;
            }
            if (0 != share_shuffle_upstream(input, numElements, true)) {
                cout<<"share_shuffle_upstream error"<<endl;
                return -1;
            }
            if (0 != share_shuffle_passive(input, numElements)) {
                cout<<"share_shuffle_passive error"<<endl;
                return -1;
            }
            break;
        default:
            return -1;
    }

    return 0;
}

int Utilities3Parties::sort(vector<vector<byte>*> & input, size_t numElements, vector<byte> & sortParamFirst, vector<byte> & sortParamSecond, bool malicious, bool sortWithID){

    //The sort computes the quick sort algorithm.
    std::vector<quicksort_part> sort_parts, sort_n_parts;
    int count = sortParamFirst.size();
    int elementSize = count/numElements;

    pair<vector<byte>, vector<byte>> partition_input, partition_output;
    vector<byte> partition_compRes;

    partition_input.first.resize(2 * count);
    partition_input.second.resize(2 * count);

    sort_parts.reserve(count / 10);
    sort_n_parts.reserve(count / 10);


    //In the beginning there is one part to sort, which is the whole vector.
    //During the partition function, more parts will be added (every time both halfs of the sorted part)
    // until reaching a part with one value which is sorted.
    sort_parts.emplace_back(quicksort_part { 0, numElements });

    int round = 0;

    //Continue while there are parts to sort
    while (0 != sort_parts.size()) {
        if (!partition(input, sortParamFirst, sortParamSecond, sort_parts, sort_n_parts, partition_input, partition_output, partition_compRes, malicious, sortWithID, elementSize)) {
            cout<<"partition failure"<<endl;
            return -1;

        } else {
//            cout<<"partition success; "<<sort_parts.size()<<" new parts."<<endl;
            if (sort_parts.size() > count / 10){
                cout<<"too much parts"<<endl;
            }
        }

        round++;
    }
//    cout<<"tree depth was "<< round<<endl;
    return 0;
}

bool Utilities3Parties::partition(vector<vector<byte>*> & input, vector<byte> & sortParamFirst, vector<byte> & sortParamSecond, vector<quicksort_part> &parts, vector<quicksort_part> &nparts,
                              pair<vector<byte>, vector<byte>> &part_input, pair<vector<byte>, vector<byte>> &part_output,
                              vector<byte> &part_compRes, bool malicious, bool sortWithID, int elementSize) {
    //TODO pivot selection!!
    // Prepare data for circuit
//    cout<<parts.size()<<" parts partition start."<<endl;

//    if (select_pivot_ && !pivot_selection(k_v, v_v, r_v, parts, malicious)) {
//        log4cpp::Category::getInstance(cat_).error(
//                "%s: pivot selection failed.", __FUNCTION__);
//    }

    size_t count = 0;

    //In order to sort the vector, we need to compare each value in it to the pivot.
    //We do that using a compare circuit that gets pairs of elements - element from the vector and the pivot.
    //The circuit wil return for each pair 0 - if the value is smaller or equal to the pivot and 1 - if the value os
    // bigger than the pivot
    for (vector<quicksort_part>::const_iterator qpart = parts.begin(); qpart != parts.end(); ++qpart) {
        const size_t span = qpart->high - qpart->low;
        size_t pivot = qpart->high - 1;
#pragma GCC ivdep

        //Copy the pairs to the ciruit input
        for (size_t i = 0; i < span; ++i) {
            memcpy(part_input.first.data() + 2 * (count + i) * elementSize, sortParamFirst.data() + (qpart->low + i) * elementSize, elementSize);
            memcpy(part_input.second.data() + 2 * (count + i) * elementSize, sortParamSecond.data() + (qpart->low + i) * elementSize, elementSize);
            memcpy(part_input.first.data() + (2 * (count + i) + 1) * elementSize, sortParamFirst.data() + pivot*elementSize, elementSize);
            memcpy(part_input.second.data() + (2 * (count + i) + 1) * elementSize, sortParamSecond.data() + pivot*elementSize, elementSize);
        }

        count += span;
    }

    if (count < minvf_ || workers_.size() == 0) {
        if (0 != inline_circuit(count, 2*elementSize, count*elementSize, part_input, part_output, part_compRes, malicious, comps_, true)) {
            cout<<"inline compare computation of "<<count<< " pairs failure."<<endl;
            return false;
        }
    } else {
        if (workers_compare(count, 2*elementSize, count*elementSize, part_input, part_output, part_compRes, malicious, comps_, true)) {
            cout<<"workers compare computation of "<<count<<" pairs failure."<<endl;
            return false;
        }
    }

    //Swap the shares according to the circuit results
    if (0 < workers_.size() && 1 < parts.size()) {
        workers_swap(input, parts, nparts, part_compRes, sortWithID);
    } else {
        inline_swap(input, parts, nparts, part_compRes, sortWithID, elementSize);
    }

    return true;
}

void Utilities3Parties::workers_swap(vector<vector<byte>*> & input, vector<quicksort_part> &parts, vector<quicksort_part> &nparts, vector<byte> &compRes, bool sortWithID) {

    nparts.clear();
    nparts.reserve(parts.size() * 2);

    size_t compres_base = 0, countparts = 0, countworks = workers_.size();

    for (std::vector<quicksort_part>::const_iterator qpart = parts.begin(); qpart != parts.end(); ++qpart) {

        circuit_thread::ct_task_t task;
        task.tid = countparts;
        task.ct_type = circuit_thread::ct_task_t::ct_swap;
        task.u.swap.cr = (vu_t*)compRes.data();
        task.u.swap.sharesPointers = &input;
        task.u.swap.crbase = compres_base;
        task.u.swap.numElements = numElements;
        task.u.swap.low = qpart->low;
        task.u.swap.high = qpart->high;

        workers_[countparts % countworks]->iq_.push(task);
        compres_base += task.u.swap.high - task.u.swap.low;
        countparts++;

        if (countparts >= (countworks * g_qsize)
            || parts.end() == std::next(qpart)) {
            for (size_t i = 0; i < countparts; ++i) {
                workers_[i % countworks]->oq_.pop(task);
                if (1 < task.u.swap.pivot - task.u.swap.low) {
                    nparts.emplace_back( quicksort_part { task.u.swap.low, task.u.swap.pivot });
                }
                if (1 < task.u.swap.high - (task.u.swap.pivot + 1)) {
                    nparts.emplace_back(quicksort_part { task.u.swap.pivot + 1,
                                                         task.u.swap.high });
                }
            }
            countparts = 0;
        }
    }

    parts.swap(nparts);
}

void Utilities3Parties::inline_swap(vector<vector<byte>*> & input, vector<quicksort_part> &parts, vector<quicksort_part> &nparts, vector<byte> &compRes, bool sortWithID, int elementSize) {
    nparts.clear();
    nparts.reserve(parts.size() * 2);

    size_t compres_base = 0;

    //Go over the compare parts and swap the elements according to the compare results
    for (vector<quicksort_part>::const_iterator qpart = parts.begin(); qpart != parts.end(); ++qpart) {

        size_t pivot = qpart->high - 1;

        //i1 will hold the lowest value that is bigger than the pivot
        int i1 = qpart->low;
        //i0 will hold the higher value that is smaller or equal to the pivot
        int i0 = qpart->high - 2;

        while (i1 < i0) {
            if (0 == compRes[(i1 - qpart->low + compres_base)*elementSize]) {
                ++i1;
                continue;
            }
            if (0 != compRes[(i0 - qpart->low + compres_base)*elementSize]) {
                --i0;
                continue;
            }

            //Swap the elements in indices i1 and i0
//            cout<<"swap "<<i1<<" with "<<i0<<endl;
            sharesSwap(input, i1, i0, sortWithID);
            swap(compRes[(i1 - qpart->low + compres_base)*elementSize], compRes[(i0 - qpart->low + compres_base)*elementSize]);
        }

        if (0 != compRes[(i1 - qpart->low + compres_base)*elementSize]) { //The pivot is less than i1 so swap them
//            cout<<"swap "<<i1<<" with (pivot) "<<pivot<<endl;
            sharesSwap(input, i1, pivot, sortWithID);
            swap(compRes[(i1 - qpart->low + compres_base)*elementSize], compRes[(pivot - qpart->low + compres_base)*elementSize]);
            pivot = i1;
        }

        //Add both sides of the pivot to the parts array
        if (1 < pivot - qpart->low) {
            nparts.emplace_back(quicksort_part { qpart->low, pivot });
        }
        if (1 < qpart->high - (pivot + 1)) {
            nparts.emplace_back(quicksort_part { pivot + 1, qpart->high });
        }
        compres_base += qpart->high - qpart->low;

    }

    parts.swap(nparts);
}

void Utilities3Parties::sharesSwap(vector<vector<byte>*> & input, int lIndex, int rIndex, bool sortWithID) {

    for (int i=0; i<input.size(); i++){
        //Swap each shares vector according to the given indices
        swapElement(*input[i], lIndex, rIndex, input[i]->size() / numElements);
    }

}

void Utilities3Parties::swapElement(vector<byte> & v, int lIndex, int rIndex, int elementSize){
    vector<byte> tmp(elementSize);

    //Save the element in the left index in a temp array
    memcpy(tmp.data(), v.data() + lIndex * elementSize, elementSize);
    //Copy the element from the right index to the left index
    memcpy(v.data() + lIndex * elementSize, v.data() + rIndex * elementSize, elementSize);
    //Copy the left element to the right index
    memcpy(v.data() + rIndex * elementSize, tmp.data(), elementSize);
}

int Utilities3Parties::inline_circuit(int count, int inputSize, int outputSize, pair<vector<byte>, vector<byte>> &input,
                                  pair<vector<byte>, vector<byte>> &output, vector<byte> &compRes, bool malicious, CircMap & cSpec, bool toOpen) {
    // Execute circuit
    CircMap::iterator vc = cSpec.begin();
    while (vc != cSpec.end() && vc->first < count) {
        vc++;
    }

    if (cSpec.end() == vc) {
        cout<<"failed to locate a compare circuit of size "<<count<<"."<<endl;
        return -1;
    }

    size_t csize = vc->first;
//    cout<<"inputSize = "<<inputSize<<" csize = "<<csize<<" ";

    input.first.resize(inputSize * csize, 0);
    input.second.resize(inputSize * csize, 0);

    if (toOpen) {
        compRes.resize(outputSize/count*csize);
    }

    size_t input_size_vu = input.first.size()/sizeof(vu_t);
    size_t output_size_vu = vc->second.get_output_sequence().size();
    output.first.resize(output_size_vu*sizeof(vu_t));
    output.second.resize(output_size_vu*sizeof(vu_t));

    if (malicious) {

        if (0 != circuit->m_vcompute(vc->second, csize, input_size_vu, (vu_t*)input.first.data(), (vu_t*)input.second.data(),
                                     output_size_vu, (vu_t*)output.first.data(), (vu_t*)output.second.data())) {
            cout<<"comp-"<<csize<<" circuit.vcompute() failure."<<endl;
            return -1;
        }
        if (toOpen) {
            if (0 != circuit->m_share_open(-1, compRes.size()/ sizeof(vu_t), (vu_t*)output.first.data(),
                                           (vu_t*) output.second.data(), (vu_t*)compRes.data())) {
                cout << "comp-" << csize << " circuit.share_open() failure." << endl;
                return -1;
            }
        }
    } else {

        if (0 != circuit->s_vcompute(vc->second, csize, input_size_vu, (vu_t*)input.first.data(), (vu_t*)input.second.data(),
                                     output_size_vu, (vu_t*)output.first.data(), (vu_t*)output.second.data())) {
            cout<<"comp-"<<csize<<" circuit.vcompute() failure."<<endl;
            return -1;
        }

        if (toOpen) {

            if (0 != circuit->s_share_open(-1, compRes.size()/sizeof(vu_t), (vu_t*)output.first.data(),
                                           (vu_t*) output.second.data(), (vu_t*)compRes.data())) {
                cout << "comp-" << csize << " circuit.share_open() failure." << endl;
                return -1;
            }

        }
    }

    if (!toOpen) {
        output.first.resize(outputSize);
        output.second.resize(outputSize);
    }


    return 0;
}

int Utilities3Parties::workers_compare(int count, int inputSize, int outputSize, pair<vector<byte>, vector<byte>> &input,
                                   pair<vector<byte>, vector<byte>> &output, vector<byte> &compRes, bool malicious, CircMap & cSpec, bool toOpen) {

    circuit_thread::ct_task_t task;
    size_t chunks = 0, vf = 0, csize = 0, cid = 0;

    select_cdc(count, chunks, vf);
//    cout<<"count = "<<count<<" cdc selection: "<<chunks<<" chunks of "<<vf<<" vf;"<<endl;
    csize = chunks * vf;
    input.first.resize(inputSize * csize);
    input.second.resize(inputSize * csize);
    if (toOpen) {
        compRes.resize(outputSize/count*csize);
    }

//    cout<<"compRes size = "<<compRes.size() / sizeof(vu_t)<<endl;
    for (size_t c = 0; c < chunks; c++) {

        task.tid = c;
        task.ct_type = circuit_thread::ct_task_t::ct_compare;
        task.u.comp.malicious = malicious;
        task.u.comp.ccm_ = &cSpec;
        task.u.comp.size = vf;
        task.u.comp.i1 = (vu_t*)input.first.data() + (c * 2 * vf);
        task.u.comp.i2 = (vu_t*)input.second.data() + (c * 2 * vf);
        task.u.comp.op = (vu_t*)compRes.data() + (c * vf);

//        cout<<"compare task "<<task.tid<<"; size="<<task.u.comp.size<<"; input offset = "<<(c * 2 * vf)<<"; output offset = "<<(c * vf)<<";"<<endl;

        cid = c % workers_.size();
        if (0 != workers_[cid]->iq_.push(task)) {
            cout<<"circuiter["<<cid<<"].iq_.push() failure."<<endl;
            return -1;
        }
    }

    for (size_t c = 0; c < chunks; c++) {
        cid = c % workers_.size();
        if (0 != workers_[cid]->oq_.pop(task)) {
            cout<<"circuiter["<<cid<<"].oq_.pop() failure."<<endl;
            return -1;
        }
    }

    return 0;
}


void Utilities3Parties::select_cdc(size_t count, size_t & chunks, size_t & vf) {
    cdc x(1, count);
    set<cdc>::const_iterator itr = scale_.find(x);
    if (scale_.end() == itr) {
        itr = scale_.upper_bound(x);
    }

    if (scale_.end() == itr) {
        vf = maxvf_;
        chunks = (count + vf - 1) / vf;
    } else {
        vf = itr->get_vf();
        chunks = itr->get_chunks();
    }
}



bool Utilities3Parties::load_compare_circuits(const char * comp_deep_circuit, const char * comp_shallow_circuit) {
    const size_t max_shallow_vf = g_comparison_circuit_threshold;
    const size_t min_deep_vf = (max_shallow_vf << 1);
    cout<<"minvf_="<<minvf_<<"; max_shallow_vf="<<max_shallow_vf<<"; min_deep_vf="<<min_deep_vf<<"; maxvf_="<<maxvf_<<"."<<endl;
    if (max_shallow_vf >= minvf_) {
        if (!load_circuits_helper(comp_shallow_circuit, minvf_,
                                  std::min(max_shallow_vf, maxvf_), comps_)) {
            cout<<"load compare circuit for the shallows failure."<<endl;
            return false;
        }
    }

    if (min_deep_vf <= maxvf_) {
        if (!load_circuits_helper(comp_deep_circuit,
                                  std::max(min_deep_vf, minvf_), maxvf_, comps_)) {
            cout<<"load compare circuit for the deeps failure."<<endl;
            return false;
        }
    }

    return true;
}

bool Utilities3Parties::loadCircuitFromFile(CircuitSpec & csplain, const char * txtName,  const char * binName, bool toSerialize){
    if (toSerialize) {
        if (0 != csplain.load(txtName)) {
            cout << "failed to load circuit [" << txtName << "]" << endl;
            return false;
        } else {
            cout << "successful load of circuit [" << txtName << "]" << endl;
        }
        csplain.serialize(binName);

    } else {
        if (0 != csplain.deserialize(binName)) {
            cout << "failed to load circuit [" << binName << "]" << endl;
            return false;
        } else {
            cout << "successful load of circuit [" << binName << "]" << endl;
        }
    }
    return true;
}

bool Utilities3Parties::load_circuits_helper(const char * circuit, size_t vf_start, size_t vf_stop, CircMap & comps) {
    cout<<"circuit "<<circuit<<" @vectorization range "<<vf_start<<" - "<<vf_stop<<"."<<endl;
    CircuitSpec csplain;
    if (0 != csplain.load(circuit)) {
        cout<<"failed to load circuit ["<<circuit<<"]"<<endl;
        return false;
    } else {
        cout<<"successful load of circuit [circuit]"<<endl;
    }

    CircuitSpec vspec;
    for (size_t i = vf_start; i < vf_stop + 1; i *= 2) {
        if (0 != CircuitSpec::vectorize_spec(i, csplain, vspec)) {
            cout<<"failed to "<<i<<"-vectorize circuit ["<<circuit<<"]"<<endl;
            return false;
        } else {
            cout<<"successful "<<i<<"-vectorization of  circuit ["<<circuit<<"]"<<endl;
        }

        if (!comps.insert(CircMap::value_type(i, vspec)).second) {
            cout<<i<<"-vectorized circuit mapping failure."<<endl;
            return false;
        } else {
            cout<<i<<"-vectorized circuit mapped."<<endl;
        }
    }

    return true;
}

int Utilities3Parties::init_scale() {
    for (size_t chunks = workers_.size(); chunks >= 1; --chunks) {
        for (size_t vf = maxvf_; vf >= minvf_; vf = vf >> 1) {
            cdc x(vf, chunks);
            if (scale_.end() == scale_.find(x)) {
                scale_.insert(x);
            }
        }
    }
    return scale_.size() > 0 ? 0 : -1;
}