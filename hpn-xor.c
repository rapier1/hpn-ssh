#include <string.h>
#include "hpn-xor.h"

// Architecture-specific intrinsics
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #define HPN_XOR_X86
    #include <emmintrin.h>  // SSE2
    #ifdef __AVX2__
    #include <immintrin.h>  // AVX2
    #endif
#elif defined(__aarch64__) || defined(_M_ARM64) || defined(__arm__) || defined(_M_ARM)
    #define HPN_XOR_ARM
    #include <arm_neon.h>
#endif

void hpn_xor_buffers(const void *plaintext, const void *keystream, 
                     void *ciphertext, size_t len) {
    const uint8_t *p = (const uint8_t*)plaintext;
    const uint8_t *k = (const uint8_t*)keystream;
    uint8_t *c = (uint8_t*)ciphertext;
    size_t i = 0;

#ifdef HPN_XOR_X86
    #ifdef __AVX2__
    // AVX2: Process 32 bytes per iteration
    while (i + 32 <= len) {
        __m256i vp = _mm256_loadu_si256((const __m256i*)(p + i));
        __m256i vk = _mm256_loadu_si256((const __m256i*)(k + i));
        __m256i vc = _mm256_xor_si256(vp, vk);
        _mm256_storeu_si256((__m256i*)(c + i), vc);
        i += 32;
    }
    #endif

    #ifdef __SSE2__
    // SSE2: Process 16 bytes per iteration
    while (i + 16 <= len) {
        __m128i vp = _mm_loadu_si128((const __m128i*)(p + i));
        __m128i vk = _mm_loadu_si128((const __m128i*)(k + i));
        __m128i vc = _mm_xor_si128(vp, vk);
        _mm_storeu_si128((__m128i*)(c + i), vc);
        i += 16;
    }
    #endif
#endif

#ifdef HPN_XOR_ARM
    // NEON: Process 16 bytes per iteration
    while (i + 16 <= len) {
        uint8x16_t vp = vld1q_u8(p + i);
        uint8x16_t vk = vld1q_u8(k + i);
        uint8x16_t vc = veorq_u8(vp, vk);
        vst1q_u8(c + i, vc);
        i += 16;
    }
#endif

    /* it's unlikley we will have
     * leftover bytes so check to see if we can skip the
     * remaining loops */
    if (i == len)
	    return;
    
    // 64-bit operations for remaining data
    while (i + 8 <= len) {
        *(uint64_t*)(c + i) = *(const uint64_t*)(p + i) ^ 
                              *(const uint64_t*)(k + i);
        i += 8;
    }

    // Handle remaining bytes
    while (i < len) {
        c[i] = p[i] ^ k[i];
        i++;
    }
}

void hpn_xor_inplace(void *data, const void *keystream, size_t len) {
    hpn_xor_buffers(data, keystream, data, len);
}

const char* hpn_xor_implementation(void) {
#ifdef HPN_XOR_X86
    #ifdef __AVX2__
    return "AVX2 (256-bit)";
    #elif defined(__SSE2__)
    return "SSE2 (128-bit)";
    #else
    return "scalar (x86)";
    #endif
#elif defined(HPN_XOR_ARM)
    #ifdef __ARM_NEON
    return "NEON (128-bit)";
    #else
    return "scalar (ARM)";
    #endif
#else
    return "scalar (generic)";
#endif
}
