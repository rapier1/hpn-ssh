#ifndef HPN_XOR_H
#define HPN_XOR_H

#include <stdint.h>
#include <stddef.h>

/*
 * High-performance XOR operations for HPN-SSH cipher implementations.
 * Automatically uses SIMD (AVX2, SSE2, NEON) when available.
 */

/* 
 * XOR two buffers and store result in destination.
 * This is the primary function for cipher operations.
 * 
 * Parameters:
 *   plaintext: Input data to encrypt/decrypt
 *   keystream: Cipher keystream to XOR with
 *   ciphertext: Output buffer for result
 *   len: Number of bytes to process
 * 
 * Note: All buffers must be at least 'len' bytes. Buffers may overlap
 * only if plaintext == ciphertext (in-place operation).
 */
void hpn_xor_buffers(const void *, const void *, 
                     void *, size_t);

/*
 * In-place XOR - XORs keystream into data buffer.
 * This is optimized for the common case where plaintext == ciphertext.
 * 
 * Parameters:
 *   data: Buffer containing plaintext, will be overwritten with ciphertext
 *   keystream: Cipher keystream to XOR with
 *   len: Number of bytes to process
 */
void hpn_xor_inplace(void *, const void *, size_t);

/*
 * Query the XOR implementation being used.
 * Useful for logging and diagnostics.
 * 
 * Returns: String describing the implementation (e.g., "AVX2", "NEON", "scalar")
 */
const char* hpn_xor_implementation(void);

#endif /* HPN_XOR_H */
