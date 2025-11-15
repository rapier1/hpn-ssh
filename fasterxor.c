/*
 * Copyright (c) 2022 The Board of Trustees of Carnegie Mellon University.
 *
 *  Author: Chris Rapier <rapier@psc.edu>
 *
 * This library or code is free software; you can redistribute it and/or
 * modify it under the terms of the BSD 2 Clause License.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the BSD 2-Clause License
 * for more details.
 *
 * You should have received a copy of the BSD 2-Clause License along with this
 * code, if not, see https://opensource.org/license/bsd-2-clause.
 *
 * Note: it shames me to say this but this code was originally developed
 * using Claude AI v4.5. I blame my unfamiliarity with intrinsics. This
 * AI generated code has been validated as functional and secure.
 */

#include "fasterxor.h"

// Fast XOR of src with key, storing result in dst
void faster_xor(char* RESTRICT dst, const char* RESTRICT src, const char* RESTRICT key, size_t len, size_t key_len) {
    size_t i = 0;
    
    #if defined(__AVX2__)
    // Process 32 bytes at a time with AVX2 (x86_64)
    if (key_len >= 32) {
        for (; i + 32 <= len; i += 32) {
            size_t key_idx = i % key_len;
            __m256i a = _mm256_loadu_si256((__m256i*)(src + i));
            __m256i b = _mm256_loadu_si256((__m256i*)(key + key_idx));
            __m256i result = _mm256_xor_si256(a, b);
            _mm256_storeu_si256((__m256i*)(dst + i), result);
        }
    }
    #endif
    
    #if defined(__ARM_NEON) || defined(__aarch64__)
    // Process 16 bytes at a time with NEON (ARM)
    if (key_len >= 16) {
        for (; i + 16 <= len; i += 16) {
            size_t key_idx = i % key_len;
            uint8x16_t a = vld1q_u8((uint8_t*)(src + i));
            uint8x16_t b = vld1q_u8((uint8_t*)(key + key_idx));
            uint8x16_t result = veorq_u8(a, b);
            vst1q_u8((uint8_t*)(dst + i), result);
        }
    }
    #elif defined(__SSE2__)
    // Process 16 bytes at a time with SSE2 (x86_64)
    if (key_len >= 16) {
        for (; i + 16 <= len; i += 16) {
            size_t key_idx = i % key_len;
            __m128i a = _mm_loadu_si128((__m128i*)(src + i));
            __m128i b = _mm_loadu_si128((__m128i*)(key + key_idx));
            __m128i result = _mm_xor_si128(a, b);
            _mm_storeu_si128((__m128i*)(dst + i), result);
        }
    }
    #endif
    
    // Process 8 bytes at a time
    if (key_len >= 8) {
        for (; i + 8 <= len; i += 8) {
            size_t key_idx = i % key_len;
            *(uint64_t*)(dst + i) = *(uint64_t*)(src + i) ^ *(uint64_t*)(key + key_idx);
        }
    }
    
    // Process remaining bytes
    for (; i < len; i++) {
        dst[i] = src[i] ^ key[i % key_len];
    }
}

// Optimized version for when key_len is a power of 2 (uses bitwise AND instead of modulo)
void faster_xor2(char* RESTRICT dst, const char* RESTRICT src, const char* RESTRICT key, size_t len, size_t key_len) {
    size_t i = 0;
    size_t key_mask = key_len - 1;  // For power of 2, modulo = bitwise AND with (n-1)
    
    #if defined(__AVX2__)
    if (key_len >= 32) {
        for (; i + 32 <= len; i += 32) {
            size_t key_idx = i & key_mask;
            __m256i a = _mm256_loadu_si256((__m256i*)(src + i));
            __m256i b = _mm256_loadu_si256((__m256i*)(key + key_idx));
            __m256i result = _mm256_xor_si256(a, b);
            _mm256_storeu_si256((__m256i*)(dst + i), result);
        }
    }
    #endif
    
    #if defined(__ARM_NEON) || defined(__aarch64__)
    if (key_len >= 16) {
        for (; i + 16 <= len; i += 16) {
            size_t key_idx = i & key_mask;
            uint8x16_t a = vld1q_u8((uint8_t*)(src + i));
            uint8x16_t b = vld1q_u8((uint8_t*)(key + key_idx));
            uint8x16_t result = veorq_u8(a, b);
            vst1q_u8((uint8_t*)(dst + i), result);
        }
    }
    #elif defined(__SSE2__)
    if (key_len >= 16) {
        for (; i + 16 <= len; i += 16) {
            size_t key_idx = i & key_mask;
            __m128i a = _mm_loadu_si128((__m128i*)(src + i));
            __m128i b = _mm_loadu_si128((__m128i*)(key + key_idx));
            __m128i result = _mm_xor_si128(a, b);
            _mm_storeu_si128((__m128i*)(dst + i), result);
        }
    }
    #endif
    
    if (key_len >= 8) {
        for (; i + 8 <= len; i += 8) {
            size_t key_idx = i & key_mask;
            *(uint64_t*)(dst + i) = *(uint64_t*)(src + i) ^ *(uint64_t*)(key + key_idx);
        }
    }
    
    for (; i < len; i++) {
        dst[i] = src[i] ^ key[i & key_mask];
    }
}
