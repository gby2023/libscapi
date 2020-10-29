#include "libscapi/include/cryptoInfra/protocolUtilities/MPCCircuit/bit_matrix.h"

#include <mmintrin.h>
#include <xmmintrin.h>
#include <immintrin.h>

void BitMatrix::bit_transpose_8x1(const u_int8_t * src, const size_t sstride,
		u_int8_t * dst, const size_t dstride) {

	__m64 source = _mm_set_pi8(src[sstride * 0], src[sstride * 1],
			src[sstride * 2], src[sstride * 3], src[sstride * 4],
			src[sstride * 5], src[sstride * 6], src[sstride * 7]);
	for (size_t i = 0; i < 8; ++i) {
		dst[dstride * i] = _mm_movemask_pi8(source);
		source = _mm_slli_si64(source, 1);
	}
}

void BitMatrix::bit_transpose_16x1(const u_int8_t * src, const size_t sstride,
		u_int8_t * dst, const size_t dstride) {
	__m128i source = _mm_set_epi8(src[sstride * 0], src[sstride * 1],
			src[sstride * 2], src[sstride * 3], src[sstride * 4],
			src[sstride * 5], src[sstride * 6], src[sstride * 7],
			src[sstride * 8], src[sstride * 9], src[sstride * 10],
			src[sstride * 11], src[sstride * 12], src[sstride * 13],
			src[sstride * 14], src[sstride * 15]);

	for (size_t i = 0; i < 8; ++i) {
		*((u_int16_t *) (dst + (dstride * i))) = htobe16(
				(u_int16_t )_mm_movemask_epi8(source));
		source = _mm_slli_epi64(source, 1);
	}
}

void BitMatrix::bit_transpose_32x1(const u_int8_t * src, const size_t sstride,
		u_int8_t * dst, const size_t dstride) {

	__m256i source = _mm256_set_epi8(src[sstride * 0], src[sstride * 1],
			src[sstride * 2], src[sstride * 3], src[sstride * 4],
			src[sstride * 5], src[sstride * 6], src[sstride * 7],
			src[sstride * 8], src[sstride * 9], src[sstride * 10],
			src[sstride * 11], src[sstride * 12], src[sstride * 13],
			src[sstride * 14], src[sstride * 15], src[sstride * 16],
			src[sstride * 17], src[sstride * 18], src[sstride * 19],
			src[sstride * 20], src[sstride * 21], src[sstride * 22],
			src[sstride * 23], src[sstride * 24], src[sstride * 25],
			src[sstride * 26], src[sstride * 27], src[sstride * 28],
			src[sstride * 29], src[sstride * 30], src[sstride * 31]);

	for (size_t i = 0; i < 8; ++i) {
		*((u_int32_t *) (dst + (dstride * i))) = htobe32(
				(u_int32_t )_mm256_movemask_epi8(source));
		source = _mm256_slli_epi64(source, 1);
	}
}

#ifdef PATCHED_AVX512FINTRIN_H
#include <avx512fintrin.h>
#include "avx512fintrin_patch.h"
void BitMatrix::bit_transpose_64x1(const u_int8_t * src, const size_t sstride,
		u_int8_t * dst, const size_t dstride) {
	__m512i source = _mm512_set_epi8 (src[sstride * 0], src[sstride * 1],
			src[sstride * 2], src[sstride * 3], src[sstride * 4],
			src[sstride * 5], src[sstride * 6], src[sstride * 7],
			src[sstride * 8], src[sstride * 9], src[sstride * 10],
			src[sstride * 11], src[sstride * 12], src[sstride * 13],
			src[sstride * 14], src[sstride * 15], src[sstride * 16],
			src[sstride * 17], src[sstride * 18], src[sstride * 19],
			src[sstride * 20], src[sstride * 21], src[sstride * 22],
			src[sstride * 23], src[sstride * 24], src[sstride * 25],
			src[sstride * 26], src[sstride * 27], src[sstride * 28],
			src[sstride * 29], src[sstride * 30], src[sstride * 31],
			src[sstride * 32], src[sstride * 33], src[sstride * 34],
			src[sstride * 35], src[sstride * 36], src[sstride * 37],
			src[sstride * 38], src[sstride * 39], src[sstride * 40],
			src[sstride * 41], src[sstride * 42], src[sstride * 43],
			src[sstride * 44], src[sstride * 45], src[sstride * 46],
			src[sstride * 47], src[sstride * 48], src[sstride * 49],
			src[sstride * 50], src[sstride * 51], src[sstride * 52],
			src[sstride * 53], src[sstride * 54], src[sstride * 55],
			src[sstride * 56], src[sstride * 57], src[sstride * 58],
			src[sstride * 59], src[sstride * 60], src[sstride * 61],
			src[sstride * 62], src[sstride * 63]);

	for (size_t i = 0; i < 8; ++i) {
		*((u_int64_t *) (dst + (dstride * i))) = htobe64(
				(u_int64_t )_mm512_movepi8_mask(source));
		source = _mm512_slli_epi64(source, 1);
	}
}
#endif

int BitMatrix::bit_transpose_byte_matrix(const u_int8_t * src,
		const size_t rows, const size_t cols, u_int8_t * dst) {
	if (0 != rows % 8) {
		return -1;
	}

 	size_t dcols = rows / 8;
	for (size_t scol = 0; scol < cols; scol += 1) {
		for (size_t srow = 0; srow < rows;) {
			size_t src_offset = (srow * cols + scol), dst_offset = (8 * scol
					* dcols + srow / 8);
#ifdef PATCHED_AVX512FINTRIN_H
			if ((rows - srow) >= 64) {
				bit_transpose_64x1(src + src_offset, cols, dst + dst_offset,
						dcols);
				srow += 64;
			} else
#endif
			if ((rows - srow) >= 32) {
				bit_transpose_32x1(src + src_offset, cols, dst + dst_offset,
						dcols);
				srow += 32;
			} else if ((rows - srow) >= 16) {
				bit_transpose_16x1(src + src_offset, cols, dst + dst_offset,
						dcols);
				srow += 16;
			} else if ((rows - srow) >= 8) {
				bit_transpose_8x1(src + src_offset, cols, dst + dst_offset,
						dcols);
				srow += 8;
			} else {
				return -1;
			}
		}
	}
	return 0;
}

