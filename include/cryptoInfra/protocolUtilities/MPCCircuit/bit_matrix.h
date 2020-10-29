#pragma once

#include <cstdlib>

class BitMatrix {
public:
	/*
	 Perform bit-transpose of matrix rows X cols; rows and cols in bytes; rows must be 0 mod 8;
	 */
	static int bit_transpose_byte_matrix(const u_int8_t * src,
			const size_t rows, const size_t cols, u_int8_t * dst);
	/*
	 Perform bit-transpose of 8 byte vector; sstride/dstride the distance between source/dest bytes;
	 */
	static void bit_transpose_8x1(const u_int8_t * src, const size_t sstride,
			u_int8_t * dst, const size_t dstride);
	/*
	 Perform bit-transpose of 16 byte vector; sstride/dstride the distance between source/dest bytes;
	 */
	static void bit_transpose_16x1(const u_int8_t * src, const size_t sstride,
			u_int8_t * dst, const size_t dstride);
	/*
	 Perform bit-transpose of 32 byte vector; sstride/dstride the distance between source/dest bytes;
	 */
	static void bit_transpose_32x1(const u_int8_t * src, const size_t sstride,
			u_int8_t * dst, const size_t dstride);
#ifdef PATCHED_AVX512FINTRIN_H
	/*
	 Perform bit-transpose of 64 byte vector; sstride/dstride the distance between source/dest bytes;
	 */
	static void bit_transpose_64x1(const u_int8_t * src, const size_t sstride,
		u_int8_t * dst, const size_t dstride);
#endif
};
