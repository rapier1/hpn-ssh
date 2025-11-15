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

#include <stdint.h>
#include <stddef.h>

#if defined(__GNUC__)
    #define RESTRICT __restrict__
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
    #define RESTRICT restrict
#else
    #define RESTRICT
#endif

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #include <immintrin.h>
    #define USEFASTERXOR
#elif defined(__ARM_NEON) || defined(__aarch64__)
    #include <arm_neon.h>
    #define USEFASTERXOR
#endif

void faster_xor2(char* RESTRICT , const char* RESTRICT, const char* RESTRICT, size_t, size_t);
void faster_xor(char* RESTRICT, const char* RESTRICT, const char* RESTRICT, size_t, size_t);
