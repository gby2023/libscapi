#pragma once

#include <vector>
#include "aligned_allocator.h"

//64 byte aligned byte vector:

typedef unsigned char byte;
typedef u_int32_t vu_t; //definition of vector unit; replace with u_int8_t/u_int16_t/u_int32_t/u_int64_t as needed.
typedef std::vector<vu_t, aligned_allocator<vu_t, 64> > Align64Vctr;
typedef Align64Vctr ClrVctr;
typedef Align64Vctr CorrRndVctr;
typedef std::pair<Align64Vctr, Align64Vctr> RepShrVctr;

typedef vu_t key_type;
typedef std::vector<key_type, aligned_allocator<key_type, 64>> Align64KeyVctr;
typedef std::pair<Align64KeyVctr, Align64KeyVctr> KeyRepShrVctr;
typedef u_int64_t val_type;