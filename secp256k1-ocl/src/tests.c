/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
 /*Copyright Ilay Chen and Yakir Fenton*/

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif
#include <stdint.h>


#define NUM_OF_SIGS 100000

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

#include <stdio.h>
#include <stdlib.h>

#include <time.h>

#include "secp256k1.c"
#include "include/secp256k1.h"
#include "testrand_impl.h"

#ifdef ENABLE_OPENSSL_TESTS
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/ecdsa.h"
#include "openssl/obj_mac.h"
#endif

#if !defined(VG_CHECK)
# if defined(VALGRIND)
#  include <valgrind/memcheck.h>
#  define VG_UNDEF(x,y) VALGRIND_MAKE_MEM_UNDEFINED((x),(y))
#  define VG_CHECK(x,y) VALGRIND_CHECK_MEM_IS_DEFINED((x),(y))
# else
#  define VG_UNDEF(x,y)
#  define VG_CHECK(x,y)
# endif
#endif

#include <stdint.h>
#include <string.h>
#define MAX_SOURCE_SIZE (0x100000)

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#include <unistd.h>

# define SECP256K1_RESTRICT

#define ECMULT_WINDOW_SIZE 15 
#  define WINDOW_G ECMULT_WINDOW_SIZE
#  define WINDOW_A 5 

#define ECMULT_TABLE_SIZE(w) (1 << ((w)-2))

#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)

/* Limbs of half the secp256k1 order. */
#define SECP256K1_N_H_0 ((uint64_t)0xDFE92F46681B20A0ULL)
#define SECP256K1_N_H_1 ((uint64_t)0x5D576E7357A4501DULL)
#define SECP256K1_N_H_2 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
#define SECP256K1_N_H_3 ((uint64_t)0x7FFFFFFFFFFFFFFFULL)

#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { \
    (d0) | (((uint64_t)(d1) & 0xFFFFFUL) << 32), \
    ((uint64_t)(d1) >> 20) | (((uint64_t)(d2)) << 12) | (((uint64_t)(d3) & 0xFFUL) << 44), \
    ((uint64_t)(d3) >> 8) | (((uint64_t)(d4) & 0xFFFFFFFUL) << 24), \
    ((uint64_t)(d4) >> 28) | (((uint64_t)(d5)) << 4) | (((uint64_t)(d6) & 0xFFFFUL) << 36), \
    ((uint64_t)(d6) >> 16) | (((uint64_t)(d7)) << 16) \
}

#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)), 1, 1}

#define ECMULT_TABLE_GET_GE_STORAGE(r,pre,n,w) do { \
    if ((n) > 0) { \
        secp256k1_ge_from_storageX_m((r), (pre)[((n)-1)/2]); \
    } else { \
        secp256k1_ge_from_storageX_m((r), (pre)[(-(n)-1)/2]); \
        secp256k1_fe_negateX(&((r)->y), &((r)->y), 1); \
    } \
} while(0)

#define ECMULT_TABLE_GET_GE(r,pre,n,w) do { \
    if ((n) > 0) { \
        *(r) = (pre)[((n)-1)/2]; \
    } else { \
        *(r) = (pre)[(-(n)-1)/2]; \
        secp256k1_fe_negateX(&((r)->y), &((r)->y), 1); \
    } \
} while(0)

#define muladd(a,b) { \
    uint64_t tl, th; \
    { \
        uint128_t t = (uint128_t)a * b; \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    c2 += (c1 < th) ? 1 : 0;  /* never overflows by contract (verified in the next line) */ \
}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
#define muladd_fast(a,b) { \
    uint64_t tl, th; \
    { \
        uint128_t t = (uint128_t)a * b; \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* never overflows by contract (verified in the next line) */ \
}

/** Add 2*a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd2(a,b) { \
    uint64_t tl, th, th2, tl2; \
    { \
        uint128_t t = (uint128_t)a * b; \
        th = t >> 64;               /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    th2 = th + th;                  /* at most 0xFFFFFFFFFFFFFFFE (in case th was 0x7FFFFFFFFFFFFFFF) */ \
    c2 += (th2 < th) ? 1 : 0;       /* never overflows by contract (verified the next line) */ \
    tl2 = tl + tl;                  /* at most 0xFFFFFFFFFFFFFFFE (in case the lowest 63 bits of tl were 0x7FFFFFFFFFFFFFFF) */ \
    th2 += (tl2 < tl) ? 1 : 0;      /* at most 0xFFFFFFFFFFFFFFFF */ \
    c0 += tl2;                      /* overflow is handled on the next line */ \
    th2 += (c0 < tl2) ? 1 : 0;      /* second overflow is handled on the next line */ \
    c2 += (c0 < tl2) & (th2 == 0);  /* never overflows by contract (verified the next line) */ \
    c1 += th2;                      /* overflow is handled on the next line */ \
    c2 += (c1 < th2) ? 1 : 0;       /* never overflows by contract (verified the next line) */ \
}

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
#define sumadd(a) { \
    unsigned int over; \
    c0 += (a);                  /* overflow is handled on the next line */ \
    over = (c0 < (a)) ? 1 : 0; \
    c1 += over;                 /* overflow is handled on the next line */ \
    c2 += (c1 < over) ? 1 : 0;  /* never overflows by contract */ \
}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
#define sumadd_fast(a) { \
    c0 += (a);                 /* overflow is handled on the next line */ \
    c1 += (c0 < (a)) ? 1 : 0;  /* never overflows by contract (verified the next line) */ \
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. */
#define extract(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = c2; \
    c2 = 0; \
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. c2 is required to be zero. */
#define extract_fast(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = 0; \
}


static int count = 64;
static secp256k1_context *ctx = NULL;

typedef struct {
    uint64_t d[4];
} secp256k1_scalarX;

typedef struct {
    uint64_t n[5];
#ifdef VERIFY
    int magnitude;
    int normalized;
#endif
} secp256k1_feX;

typedef struct {
    secp256k1_feX x;
    secp256k1_feX y;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_geX;

typedef struct {
    secp256k1_feX x; /* actual X: x/z^2 */
    secp256k1_feX y; /* actual Y: y/z^3 */
    secp256k1_feX z;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_gejX;

struct secp256k1_strauss_point_stateX {
    int wnaf_na[256];
    int bits_na;
    size_t input_pos;
};

struct secp256k1_strauss_stateX {
    secp256k1_gejX* prej;
    secp256k1_feX* zr;
    secp256k1_geX* pre_a;
    struct secp256k1_strauss_point_stateX* ps;
};

typedef struct {
    uint64_t n[4];
} secp256k1_fe_storageX;

typedef struct {
    secp256k1_fe_storageX x;
    secp256k1_fe_storageX y;
} secp256k1_ge_storageX;

typedef struct {
    secp256k1_ge_storageX (*pre_g)[];
} secp256k1_ecmult_contextX;

typedef struct {
    void (*fn)(const char *text, void* data);
    const void* data;
} secp256k1_callbackX;

typedef struct {
    secp256k1_ge_storageX (*prec)[64][16];
    secp256k1_scalarX blind;
    secp256k1_gejX initial;
} secp256k1_ecmult_gen_contextX;

typedef struct secp256k1_context_structX secp256k1_contextX;

struct secp256k1_context_structX {
    secp256k1_ecmult_contextX ecmult_ctx;
    secp256k1_ecmult_gen_contextX ecmult_gen_ctx;
    secp256k1_callbackX illegal_callback;
    secp256k1_callbackX error_callback;
};

typedef struct {
    unsigned char data[64];
} secp256k1_ecdsa_signatureX;

typedef struct {
    unsigned char data[64];
} secp256k1_pubkeyX;


int secp256k1_scalar_is_zeroX(const secp256k1_scalarX *a) {
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

void secp256k1_scalar_set_intX(secp256k1_scalarX *r, unsigned int v) {
    r->d[0] = v;
    r->d[1] = 0;
    r->d[2] = 0;
    r->d[3] = 0;
}

static const secp256k1_feX secp256k1_ecdsa_const_order_as_feX = SECP256K1_FE_CONST(
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFEUL,
    0xBAAEDCE6UL, 0xAF48A03BUL, 0xBFD25E8CUL, 0xD0364141UL
);

static const secp256k1_feX secp256k1_ecdsa_const_p_minus_orderX = SECP256K1_FE_CONST(
    0, 0, 0, 1, 0x45512319UL, 0x50B75FC4UL, 0x402DA172UL, 0x2FC9BAEEUL
);

void secp256k1_scalar_inverseX(secp256k1_scalarX *r, const secp256k1_scalarX *x);
static void secp256k1_scalar_inverse_varX(secp256k1_scalarX *r, const secp256k1_scalarX *x);
static void secp256k1_scalar_reduce_512X(secp256k1_scalarX *r, const uint64_t *l);
void secp256k1_scalar_sqrX(secp256k1_scalarX *r, const secp256k1_scalarX *a);
int secp256k1_scalar_is_evenX(const secp256k1_scalarX *a);
void secp256k1_scalar_sqr_512X(uint64_t l[8], const secp256k1_scalarX *a);
int secp256k1_scalar_reduceX(secp256k1_scalarX *r, unsigned int overflow);
int secp256k1_scalar_check_overflowX(const secp256k1_scalarX *a);
static void secp256k1_scalar_mul_512X(uint64_t l[8], const secp256k1_scalarX *a, const secp256k1_scalarX *b);
void secp256k1_scalar_mulX(secp256k1_scalarX *r, const secp256k1_scalarX *a, const secp256k1_scalarX *b);
static void secp256k1_gej_set_geX(secp256k1_gejX *r, const secp256k1_geX *a);
static void secp256k1_fe_verifyX(const secp256k1_feX *a);
void secp256k1_fe_set_intX(secp256k1_feX *r, int a);
unsigned int secp256k1_scalar_get_bitsX(const secp256k1_scalarX *a, unsigned int offset, unsigned int count);
static void secp256k1_scalar_negateX(secp256k1_scalarX *r, const secp256k1_scalarX *a);
unsigned int secp256k1_scalar_get_bits_varX(const secp256k1_scalarX *a, unsigned int offset, unsigned int count);
static int secp256k1_ecmult_wnafX(int *wnaf, int len, const secp256k1_scalarX *a, int w);
void secp256k1_fe_clearX(secp256k1_feX *a);
void secp256k1_ecmult_strauss_wnafX(const secp256k1_ecmult_contextX *ctx, const struct secp256k1_strauss_stateX *state, secp256k1_gejX *r, int num, const secp256k1_gejX *a, const secp256k1_scalarX *na, const secp256k1_scalarX *ng);
int secp256k1_fe_equal_varX(const secp256k1_feX *a, const secp256k1_feX *b);






void secp256k1_scalar_inverseX(secp256k1_scalarX *r, const secp256k1_scalarX *x) {
    secp256k1_scalarX *t;
    int i;
    /* First compute xN as x ^ (2^N - 1) for some values of N,
     * and uM as x ^ M for some values of M. */
    secp256k1_scalarX x2, x3, x6, x8, x14, x28, x56, x112, x126;
    secp256k1_scalarX u2, u5, u9, u11, u13;

    secp256k1_scalar_sqrX(&u2, x);
    secp256k1_scalar_mulX(&x2, &u2,  x);
    secp256k1_scalar_mulX(&u5, &u2, &x2);
    secp256k1_scalar_mulX(&x3, &u5,  &u2);
    secp256k1_scalar_mulX(&u9, &x3, &u2);
    secp256k1_scalar_mulX(&u11, &u9, &u2);
    secp256k1_scalar_mulX(&u13, &u11, &u2);

    secp256k1_scalar_sqrX(&x6, &u13);
    secp256k1_scalar_sqrX(&x6, &x6);
    secp256k1_scalar_mulX(&x6, &x6, &u11);

    secp256k1_scalar_sqrX(&x8, &x6);
    secp256k1_scalar_sqrX(&x8, &x8);
    secp256k1_scalar_mulX(&x8, &x8,  &x2);

    secp256k1_scalar_sqrX(&x14, &x8);
    for (i = 0; i < 5; i++) {
        secp256k1_scalar_sqrX(&x14, &x14);
    }
    secp256k1_scalar_mulX(&x14, &x14, &x6);

    secp256k1_scalar_sqrX(&x28, &x14);
    for (i = 0; i < 13; i++) {
        secp256k1_scalar_sqrX(&x28, &x28);
    }
    secp256k1_scalar_mulX(&x28, &x28, &x14);

    secp256k1_scalar_sqrX(&x56, &x28);
    for (i = 0; i < 27; i++) {
        secp256k1_scalar_sqrX(&x56, &x56);
    }
    secp256k1_scalar_mulX(&x56, &x56, &x28);

    secp256k1_scalar_sqrX(&x112, &x56);
    for (i = 0; i < 55; i++) {
        secp256k1_scalar_sqrX(&x112, &x112);
    }
    secp256k1_scalar_mulX(&x112, &x112, &x56);

    secp256k1_scalar_sqrX(&x126, &x112);
    for (i = 0; i < 13; i++) {
        secp256k1_scalar_sqrX(&x126, &x126);
    }
    secp256k1_scalar_mulX(&x126, &x126, &x14);

    /* Then accumulate the final result (t starts at x126). */
    t = &x126;
    for (i = 0; i < 3; i++) {
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u5); /* 101 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &x3); /* 111 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u5); /* 101 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &x3); /* 111 */
    for (i = 0; i < 5; i++) { /* 00 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &x3); /* 111 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u13); /* 1101 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u5); /* 101 */
    for (i = 0; i < 3; i++) {
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &x3); /* 111 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 000 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u5); /* 101 */
    for (i = 0; i < 10; i++) { /* 0000000 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &x3); /* 111 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &x3); /* 111 */
    for (i = 0; i < 9; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &x8); /* 11111111 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u13); /* 1101 */
    for (i = 0; i < 5; i++) {
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &x2); /* 11 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u13); /* 1101 */
    for (i = 0; i < 10; i++) { /* 000000 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u13); /* 1101 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 00000 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(t, t, x); /* 1 */
    for (i = 0; i < 8; i++) { /* 00 */
        secp256k1_scalar_sqrX(t, t);
    }
    secp256k1_scalar_mulX(r, t, &x6); /* 111111 */
}


static void secp256k1_scalar_inverse_varX(secp256k1_scalarX *r, const secp256k1_scalarX *x) {
    secp256k1_scalar_inverseX(r, x);
}

static void secp256k1_scalar_reduce_512X(secp256k1_scalarX *r, const uint64_t *l) {
    uint128_t c;
    uint64_t c0, c1, c2;
    uint64_t n0 = l[4], n1 = l[5], n2 = l[6], n3 = l[7];
    uint64_t m0, m1, m2, m3, m4, m5;
    uint32_t m6;
    uint64_t p0, p1, p2, p3;
    uint32_t p4;

    /* Reduce 512 bits into 385. */
    /* m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C. */
    c0 = l[0]; c1 = 0; c2 = 0;
    muladd_fast(n0, SECP256K1_N_C_0);
    extract_fast(m0);
    sumadd_fast(l[1]);
    muladd(n1, SECP256K1_N_C_0);
    muladd(n0, SECP256K1_N_C_1);
    extract(m1);
    sumadd(l[2]);
    muladd(n2, SECP256K1_N_C_0);
    muladd(n1, SECP256K1_N_C_1);
    sumadd(n0);
    extract(m2);
    sumadd(l[3]);
    muladd(n3, SECP256K1_N_C_0);
    muladd(n2, SECP256K1_N_C_1);
    sumadd(n1);
    extract(m3);
    muladd(n3, SECP256K1_N_C_1);
    sumadd(n2);
    extract(m4);
    sumadd_fast(n3);
    extract_fast(m5);
    m6 = c0;

    /* Reduce 385 bits into 258. */
    /* p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C. */
    c0 = m0; c1 = 0; c2 = 0;
    muladd_fast(m4, SECP256K1_N_C_0);
    extract_fast(p0);
    sumadd_fast(m1);
    muladd(m5, SECP256K1_N_C_0);
    muladd(m4, SECP256K1_N_C_1);
    extract(p1);
    sumadd(m2);
    muladd(m6, SECP256K1_N_C_0);
    muladd(m5, SECP256K1_N_C_1);
    sumadd(m4);
    extract(p2);
    sumadd_fast(m3);
    muladd_fast(m6, SECP256K1_N_C_1);
    sumadd_fast(m5);
    extract_fast(p3);
    p4 = c0 + m6;

    /* Reduce 258 bits into 256. */
    /* r[0..3] = p[0..3] + p[4] * SECP256K1_N_C. */
    c = p0 + (uint128_t)SECP256K1_N_C_0 * p4;
    r->d[0] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
    c += p1 + (uint128_t)SECP256K1_N_C_1 * p4;
    r->d[1] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
    c += p2 + (uint128_t)p4;
    r->d[2] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
    c += p3;
    r->d[3] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;

    /* Final reduction of r. */
    secp256k1_scalar_reduceX(r, c + secp256k1_scalar_check_overflowX(r));
}

void secp256k1_scalar_sqrX(secp256k1_scalarX *r, const secp256k1_scalarX *a) {
    uint64_t l[8];
    secp256k1_scalar_sqr_512X(l, a);
    secp256k1_scalar_reduce_512X(r, l);
}

int secp256k1_scalar_is_evenX(const secp256k1_scalarX *a) {
    return !(a->d[0] & 1);
}

void secp256k1_scalar_sqr_512X(uint64_t l[8], const secp256k1_scalarX *a) {
    /* 160 bit accumulator. */
    uint64_t c0 = 0, c1 = 0;
    uint32_t c2 = 0;

    /* l[0..7] = a[0..3] * b[0..3]. */
    muladd_fast(a->d[0], a->d[0]);
    extract_fast(l[0]);
    muladd2(a->d[0], a->d[1]);
    extract(l[1]);
    muladd2(a->d[0], a->d[2]);
    muladd(a->d[1], a->d[1]);
    extract(l[2]);
    muladd2(a->d[0], a->d[3]);
    muladd2(a->d[1], a->d[2]);
    extract(l[3]);
    muladd2(a->d[1], a->d[3]);
    muladd(a->d[2], a->d[2]);
    extract(l[4]);
    muladd2(a->d[2], a->d[3]);
    extract(l[5]);
    muladd_fast(a->d[3], a->d[3]);
    extract_fast(l[6]);
    l[7] = c0;
}

int secp256k1_scalar_reduceX(secp256k1_scalarX *r, unsigned int overflow) {
    uint128_t t;
    t = (uint128_t)r->d[0] + overflow * SECP256K1_N_C_0;
    r->d[0] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[1] + overflow * SECP256K1_N_C_1;
    r->d[1] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[2] + overflow * SECP256K1_N_C_2;
    r->d[2] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint64_t)r->d[3];
    r->d[3] = t & 0xFFFFFFFFFFFFFFFFULL;
    return overflow;
}

int secp256k1_scalar_check_overflowX(const secp256k1_scalarX *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[3] < SECP256K1_N_3); 
    no |= (a->d[2] < SECP256K1_N_2);
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_1);
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

static void secp256k1_scalar_mul_512X(uint64_t l[8], const secp256k1_scalarX *a, const secp256k1_scalarX *b) {
    uint64_t c0 = 0, c1 = 0;
    uint32_t c2 = 0;

    muladd_fast(a->d[0], b->d[0]);
    extract_fast(l[0]);
    muladd(a->d[0], b->d[1]);
    muladd(a->d[1], b->d[0]);
    extract(l[1]);
    muladd(a->d[0], b->d[2]);
    muladd(a->d[1], b->d[1]);
    muladd(a->d[2], b->d[0]);
    extract(l[2]);
    muladd(a->d[0], b->d[3]);
    muladd(a->d[1], b->d[2]);
    muladd(a->d[2], b->d[1]);
    muladd(a->d[3], b->d[0]);
    extract(l[3]);
    muladd(a->d[1], b->d[3]);
    muladd(a->d[2], b->d[2]);
    muladd(a->d[3], b->d[1]);
    extract(l[4]);
    muladd(a->d[2], b->d[3]);
    muladd(a->d[3], b->d[2]);
    extract(l[5]);
    muladd_fast(a->d[3], b->d[3]);
    extract_fast(l[6]);
    l[7] = c0;
}


void secp256k1_scalar_mulX(secp256k1_scalarX *r, const secp256k1_scalarX *a, const secp256k1_scalarX *b) {
    uint64_t l[8];
    secp256k1_scalar_mul_512X(l, a, b);
    secp256k1_scalar_reduce_512X(r, l);
}

static void secp256k1_gej_set_geX(secp256k1_gejX *r, const secp256k1_geX *a) {
   r->infinity = a->infinity;
   r->x = a->x;
   r->y = a->y;
   secp256k1_fe_set_intX(&r->z, 1);
}

static void secp256k1_fe_verifyX(const secp256k1_feX *a) {
    const uint32_t *d = a->n;
    int m = a->normalized ? 1 : 2 * a->magnitude, r = 1;
    r &= (d[0] <= 0x3FFFFFFUL * m);
    r &= (d[1] <= 0x3FFFFFFUL * m);
    r &= (d[2] <= 0x3FFFFFFUL * m);
    r &= (d[3] <= 0x3FFFFFFUL * m);
    r &= (d[4] <= 0x3FFFFFFUL * m);
    r &= (d[5] <= 0x3FFFFFFUL * m);
    r &= (d[6] <= 0x3FFFFFFUL * m);
    r &= (d[7] <= 0x3FFFFFFUL * m);
    r &= (d[8] <= 0x3FFFFFFUL * m);
    r &= (d[9] <= 0x03FFFFFUL * m);
    r &= (a->magnitude >= 0);
    r &= (a->magnitude <= 32);
    if (a->normalized) {
        r &= (a->magnitude <= 1);
        if (r && (d[9] == 0x03FFFFFUL)) {
            uint32_t mid = d[8] & d[7] & d[6] & d[5] & d[4] & d[3] & d[2];
            if (mid == 0x3FFFFFFUL) {
                r &= ((d[1] + 0x40UL + ((d[0] + 0x3D1UL) >> 26)) <= 0x3FFFFFFUL);
            }
        }
    }
}

void secp256k1_fe_set_intX(secp256k1_feX *r, int a) {
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verifyX(r);
}

unsigned int secp256k1_scalar_get_bitsX(const secp256k1_scalarX *a, unsigned int offset, unsigned int count) {
    return (a->d[offset >> 6] >> (offset & 0x3F)) & ((((uint64_t)1) << count) - 1);
}

static void secp256k1_scalar_negateX(secp256k1_scalarX *r, const secp256k1_scalarX *a) {
    uint64_t nonzero = 0xFFFFFFFFFFFFFFFFULL * (secp256k1_scalar_is_zeroX(a) == 0);
    uint128_t t = (uint128_t)(~a->d[0]) + SECP256K1_N_0 + 1;
    r->d[0] = t & nonzero; t >>= 64;
    t += (uint128_t)(~a->d[1]) + SECP256K1_N_1;
    r->d[1] = t & nonzero; t >>= 64;
    t += (uint128_t)(~a->d[2]) + SECP256K1_N_2;
    r->d[2] = t & nonzero; t >>= 64;
    t += (uint128_t)(~a->d[3]) + SECP256K1_N_3;
    r->d[3] = t & nonzero;
}

unsigned int secp256k1_scalar_get_bits_varX(const secp256k1_scalarX *a, unsigned int offset, unsigned int count) {
    if ((offset + count - 1) >> 6 == offset >> 6) {
        return secp256k1_scalar_get_bitsX(a, offset, count);
    } else {
        return ((a->d[offset >> 6] >> (offset & 0x3F)) | (a->d[(offset >> 6) + 1] << (64 - (offset & 0x3F)))) & ((((uint64_t)1) << count) - 1);
    }
}

static int secp256k1_ecmult_wnafX(int *wnaf, int len, const secp256k1_scalarX *a, int w) {
    secp256k1_scalarX s;
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;

    memset(wnaf, 0, len * sizeof(wnaf[0]));

    s = *a;
    if (secp256k1_scalar_get_bitsX(&s, 255, 1)) {
        secp256k1_scalar_negateX(&s, &s);
        sign = -1;
    }

    while (bit < len) {
        int now;
        int word;
        if (secp256k1_scalar_get_bitsX(&s, bit, 1) == (unsigned int)carry) {
            bit++;
            continue;
        }

        now = w;
        if (now > len - bit) {
            now = len - bit;
        }

        word = secp256k1_scalar_get_bits_varX(&s, bit, now) + carry;

        carry = (word >> (w-1)) & 1;
        word -= carry << w;

        wnaf[bit] = sign * word;
        last_set_bit = bit;

        bit += now;
    }
    while (bit < 256) {
    }
    return last_set_bit + 1;
}

void secp256k1_fe_clearX(secp256k1_feX *a) {
    int i;
    a->magnitude = 0;
    a->normalized = 1;
    for (i=0; i<5; i++) {
        a->n[i] = 0;
    }
}


void secp256k1_fe_from_storageX_m(secp256k1_feX *r, secp256k1_fe_storageX a) {
    r->n[0] = a.n[0] & 0xFFFFFFFFFFFFFULL;
    r->n[1] = a.n[0] >> 52 | ((a.n[1] << 12) & 0xFFFFFFFFFFFFFULL);
    r->n[2] = a.n[1] >> 40 | ((a.n[2] << 24) & 0xFFFFFFFFFFFFFULL);
    r->n[3] = a.n[2] >> 28 | ((a.n[3] << 36) & 0xFFFFFFFFFFFFFULL);
    r->n[4] = a.n[3] >> 16;
    r->magnitude = 1;
    r->normalized = 1;
}

static void secp256k1_ge_from_storageX_m(secp256k1_geX *r, secp256k1_ge_storageX a) {
    secp256k1_fe_from_storageX_m(&r->x, a.x);
    secp256k1_fe_from_storageX_m(&r->y, a.y);
	/*printf("C %ul %ul %ul %ul \n", r->x.n[0], r->y.n[0], a->x.n[0], a->y.n[0]);*/
    r->infinity = 0;
}

void secp256k1_fe_from_storageX(secp256k1_feX *r, const secp256k1_fe_storageX *a) {
    r->n[0] = a->n[0] & 0xFFFFFFFFFFFFFULL;
    r->n[1] = a->n[0] >> 52 | ((a->n[1] << 12) & 0xFFFFFFFFFFFFFULL);
    r->n[2] = a->n[1] >> 40 | ((a->n[2] << 24) & 0xFFFFFFFFFFFFFULL);
    r->n[3] = a->n[2] >> 28 | ((a->n[3] << 36) & 0xFFFFFFFFFFFFFULL);
    r->n[4] = a->n[3] >> 16;
    r->magnitude = 1;
    r->normalized = 1;
}

static void secp256k1_ge_from_storageX(secp256k1_geX *r, const secp256k1_ge_storageX *a) {
	/*printf("ge C %ul %ul \n", a->x.n[0], a->y.n[0]);*/
    secp256k1_fe_from_storageX(&r->x, &a->x);
    secp256k1_fe_from_storageX(&r->y, &a->y);
	/*printf("C %ul %ul %ul %ul \n", r->x.n[0], r->y.n[0], a->x.n[0], a->y.n[0]);*/
    r->infinity = 0;
}

static void secp256k1_ecmultX(const secp256k1_ecmult_contextX *ctx, secp256k1_gejX *r, const secp256k1_gejX *a, const secp256k1_scalarX *na, const secp256k1_scalarX *ng) {
    secp256k1_gejX prej[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_feX zr[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_geX pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    struct secp256k1_strauss_point_stateX ps[1];
    struct secp256k1_strauss_stateX state;

    state.prej = prej;
    state.zr = zr;
    state.pre_a = pre_a;
    state.ps = ps;
    secp256k1_ecmult_strauss_wnafX(ctx, &state, r, 1, a, na, ng);
}

static int secp256k1_gej_is_infinityX(const secp256k1_gejX *a) {
    return a->infinity;
}

static void secp256k1_fe_normalize_weakX(secp256k1_feX *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    secp256k1_fe_verifyX(r);
#endif
}

void secp256k1_fe_mul_intX(secp256k1_feX *r, int a) {
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
    r->magnitude *= a;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}

void secp256k1_fe_mul_innerX_z(uint64_t *r, const uint64_t *a, const uint64_t * SECP256K1_RESTRICT b) {
    uint64_t c, d;
    uint64_t t3, t4, tx, u0;
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;


    /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  for 0 <= x <= 4, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  for 4 <= x <= 8, px is a shorthand for sum(a[i]*b[x-i], i=(x-4)..4)
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    d  = (uint128_t)a0 * b[3]
       + (uint128_t)a1 * b[2]
       + (uint128_t)a2 * b[1]
       + (uint128_t)a3 * b[0];
    /* [d 0 0 0] = [p3 0 0 0] */
    c  = (uint128_t)a4 * b[4];
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    d += (c & M) * R; c >>= 52;
    /* [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = d & M; d >>= 52;
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    d += (uint128_t)a0 * b[4]
       + (uint128_t)a1 * b[3]
       + (uint128_t)a2 * b[2]
       + (uint128_t)a3 * b[1]
       + (uint128_t)a4 * b[0];
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    d += c * R;
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = d & M; d >>= 52;
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = (t4 >> 48); t4 &= (M >> 4);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    c  = (uint128_t)a0 * b[0];
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    d += (uint128_t)a1 * b[4]
       + (uint128_t)a2 * b[3]
       + (uint128_t)a3 * b[2]
       + (uint128_t)a4 * b[1];
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = d & M; d >>= 52;
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    c += (uint128_t)u0 * (R >> 4);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = c & M; c >>= 52;
	/*printf("\n??? C %lu", c);
	printf("\n??? M %lu", M);
	printf("\n??? cM %lu", c & M);*/
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    c += (uint128_t)a0 * b[1]
       + (uint128_t)a1 * b[0];
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    d += (uint128_t)a2 * b[4]
       + (uint128_t)a3 * b[3]
       + (uint128_t)a4 * b[2];
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    c += (d & M) * R; d >>= 52;
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = c & M; c >>= 52;
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    c += (uint128_t)a0 * b[2]
       + (uint128_t)a1 * b[1]
       + (uint128_t)a2 * b[0];
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint128_t)a3 * b[4]
       + (uint128_t)a4 * b[3];
    /* [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c += (d & M) * R; d >>= 52;
    /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = c & M; c >>= 52;
    /* [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += d * R + t3;
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = c & M; c >>= 52;
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += t4;
    /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = c;
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}



void secp256k1_fe_mul_innerX(uint64_t *r, const uint64_t *a, const uint64_t * SECP256K1_RESTRICT b) {
    uint128_t c, d;
    uint64_t t3, t4, tx, u0;
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;


    /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  for 0 <= x <= 4, px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  for 4 <= x <= 8, px is a shorthand for sum(a[i]*b[x-i], i=(x-4)..4)
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    d  = (uint128_t)a0 * b[3]
       + (uint128_t)a1 * b[2]
       + (uint128_t)a2 * b[1]
       + (uint128_t)a3 * b[0];
    /* [d 0 0 0] = [p3 0 0 0] */
    c  = (uint128_t)a4 * b[4];
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    d += (c & M) * R; c >>= 52;
    /* [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = d & M; d >>= 52;
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    d += (uint128_t)a0 * b[4]
       + (uint128_t)a1 * b[3]
       + (uint128_t)a2 * b[2]
       + (uint128_t)a3 * b[1]
       + (uint128_t)a4 * b[0];
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    d += c * R;
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = d & M; d >>= 52;
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = (t4 >> 48); t4 &= (M >> 4);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    c  = (uint128_t)a0 * b[0];
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    d += (uint128_t)a1 * b[4]
       + (uint128_t)a2 * b[3]
       + (uint128_t)a3 * b[2]
       + (uint128_t)a4 * b[1];
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = d & M; d >>= 52;
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    c += (uint128_t)u0 * (R >> 4);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = c & M; c >>= 52;
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    c += (uint128_t)a0 * b[1]
       + (uint128_t)a1 * b[0];
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    d += (uint128_t)a2 * b[4]
       + (uint128_t)a3 * b[3]
       + (uint128_t)a4 * b[2];
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    c += (d & M) * R; d >>= 52;
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = c & M; c >>= 52;
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    c += (uint128_t)a0 * b[2]
       + (uint128_t)a1 * b[1]
       + (uint128_t)a2 * b[0];
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint128_t)a3 * b[4]
       + (uint128_t)a4 * b[3];
    /* [d 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c += (d & M) * R; d >>= 52;
    /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = c & M; c >>= 52;
    /* [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += d * R + t3;
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = c & M; c >>= 52;
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += t4;
    /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = c;
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}




static void secp256k1_fe_mulX(secp256k1_feX *r, const secp256k1_feX *a, const secp256k1_feX * SECP256K1_RESTRICT b) {

    secp256k1_fe_verifyX(a);
    secp256k1_fe_verifyX(b);
    secp256k1_fe_mul_innerX(r->n, a->n, b->n);
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}

void secp256k1_fe_sqr_innerX(uint64_t *r, const uint64_t *a) {
    uint128_t c, d;
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    int64_t t3, t4, tx, u0;
    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

    /**  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    d  = (uint128_t)(a0*2) * a3
       + (uint128_t)(a1*2) * a2;
    /* [d 0 0 0] = [p3 0 0 0] */
    c  = (uint128_t)a4 * a4;
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    d += (c & M) * R; c >>= 52;
    /* [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    t3 = d & M; d >>= 52;
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    a4 *= 2;
    d += (uint128_t)a0 * a4
       + (uint128_t)(a1*2) * a3
       + (uint128_t)a2 * a2;
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    d += c * R;
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    t4 = d & M; d >>= 52;
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    tx = (t4 >> 48); t4 &= (M >> 4);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    c  = (uint128_t)a0 * a0;
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    d += (uint128_t)a1 * a4
       + (uint128_t)(a2*2) * a3;
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = d & M; d >>= 52;
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    c += (uint128_t)u0 * (R >> 4);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = c & M; c >>= 52;
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    a0 *= 2;
    c += (uint128_t)a0 * a1;
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    d += (uint128_t)a2 * a4
       + (uint128_t)a3 * a3;
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    c += (d & M) * R; d >>= 52;
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = c & M; c >>= 52;
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    c += (uint128_t)a0 * a2
       + (uint128_t)a1 * a1;
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    d += (uint128_t)a3 * a4;
    /* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c += (d & M) * R; d >>= 52;
    /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = c & M; c >>= 52;
    /* [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    c   += d * R + t3;
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = c & M; c >>= 52;
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += t4;
    /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = c;
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

static void secp256k1_fe_sqrX(secp256k1_feX *r, const secp256k1_feX *a) {
    secp256k1_fe_verifyX(a);
    secp256k1_fe_sqr_innerX(r->n, a->n);
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}

void secp256k1_fe_negateX(secp256k1_feX *r, const secp256k1_feX *a, int m) {
    secp256k1_fe_verifyX(a);
    r->n[0] = 0xFFFFEFFFFFC2FULL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x0FFFFFFFFFFFFULL * 2 * (m + 1) - a->n[4];
    r->magnitude = m + 1;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}

void secp256k1_fe_addX(secp256k1_feX *r, const secp256k1_feX *a) {
    secp256k1_fe_verifyX(a);
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
    r->magnitude += a->magnitude;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}

static void secp256k1_gej_double_varX(secp256k1_gejX *r, const secp256k1_gejX *a, secp256k1_feX *rzr) {

    secp256k1_feX t1,t2,t3,t4;
    r->infinity = a->infinity;
    if (r->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_intX(rzr, 1);
        }
        return;
    }

    if (rzr != NULL) {
        *rzr = a->y;
        secp256k1_fe_normalize_weakX(rzr);
        secp256k1_fe_mul_intX(rzr, 2);
    }

    secp256k1_fe_mulX(&r->z, &a->z, &a->y);
    secp256k1_fe_mul_intX(&r->z, 2);       /* Z' = 2*Y*Z (2) */
    secp256k1_fe_sqrX(&t1, &a->x);
    secp256k1_fe_mul_intX(&t1, 3);         /* T1 = 3*X^2 (3) */
    secp256k1_fe_sqrX(&t2, &t1);           /* T2 = 9*X^4 (1) */
    secp256k1_fe_sqrX(&t3, &a->y);
    secp256k1_fe_mul_intX(&t3, 2);         /* T3 = 2*Y^2 (2) */
    secp256k1_fe_sqrX(&t4, &t3);
    secp256k1_fe_mul_intX(&t4, 2);         /* T4 = 8*Y^4 (2) */
    secp256k1_fe_mulX(&t3, &t3, &a->x);    /* T3 = 2*X*Y^2 (1) */
    r->x = t3;
    secp256k1_fe_mul_intX(&r->x, 4);       /* X' = 8*X*Y^2 (4) */
    secp256k1_fe_negateX(&r->x, &r->x, 4); /* X' = -8*X*Y^2 (5) */
    secp256k1_fe_addX(&r->x, &t2);         /* X' = 9*X^4 - 8*X*Y^2 (6) */
    secp256k1_fe_negateX(&t2, &t2, 1);     /* T2 = -9*X^4 (2) */
    secp256k1_fe_mul_intX(&t3, 6);         /* T3 = 12*X*Y^2 (6) */
    secp256k1_fe_addX(&t3, &t2);           /* T3 = 12*X*Y^2 - 9*X^4 (8) */
    secp256k1_fe_mulX(&r->y, &t1, &t3);    /* Y' = 36*X^3*Y^2 - 27*X^6 (1) */
    secp256k1_fe_negateX(&t2, &t4, 2);     /* T2 = -8*Y^4 (3) */
    secp256k1_fe_addX(&r->y, &t2);         /* Y' = 36*X^3*Y^2 - 27*X^6 - 8*Y^4 (4) */
}

static void secp256k1_ge_set_gej_zinvX(secp256k1_geX *r, const secp256k1_gejX *a, const secp256k1_feX *zi) {
    secp256k1_feX zi2;
    secp256k1_feX zi3;
    secp256k1_fe_sqrX(&zi2, zi);
    secp256k1_fe_mulX(&zi3, &zi2, zi);
    secp256k1_fe_mulX(&r->x, &a->x, &zi2);
    secp256k1_fe_mulX(&r->y, &a->y, &zi3);
    r->infinity = a->infinity;
}

static int secp256k1_fe_normalizes_to_zero_varX(secp256k1_feX *r) {
    uint64_t t0, t1, t2, t3, t4;
    uint64_t z0, z1;
    uint64_t x;

    t0 = r->n[0];
    t4 = r->n[4];

    x = t4 >> 48;

    t0 += x * 0x1000003D1ULL;

    z0 = t0 & 0xFFFFFFFFFFFFFULL;
    z1 = z0 ^ 0x1000003D0ULL;

    if ((z0 != 0ULL) & (z1 != 0xFFFFFFFFFFFFFULL)) {
        return 0;
    }

    t1 = r->n[1];
    t2 = r->n[2];
    t3 = r->n[3];

    t4 &= 0x0FFFFFFFFFFFFULL;

    t1 += (t0 >> 52);
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; z0 |= t3; z1 &= t3;
                                                z0 |= t4; z1 &= t4 ^ 0xF000000000000ULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */

    return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFULL);
}

static void secp256k1_gej_add_ge_varX(secp256k1_gejX *r, const secp256k1_gejX *a, const secp256k1_geX *b, secp256k1_feX *rzr) {
    /* 8 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    secp256k1_feX z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
    if (a->infinity) {
        secp256k1_gej_set_geX(r, b);
        return;
    }
    if (b->infinity) {
        if (rzr != NULL) {
            secp256k1_fe_set_intX(rzr, 1);
        }
        *r = *a;
        return;
    }
    r->infinity = 0;

    secp256k1_fe_sqrX(&z12, &a->z);
    u1 = a->x; secp256k1_fe_normalize_weakX(&u1);
    secp256k1_fe_mulX(&u2, &b->x, &z12);
    s1 = a->y; secp256k1_fe_normalize_weakX(&s1);
    secp256k1_fe_mulX(&s2, &b->y, &z12); secp256k1_fe_mulX(&s2, &s2, &a->z);
    secp256k1_fe_negateX(&h, &u1, 1); secp256k1_fe_addX(&h, &u2);
    secp256k1_fe_negateX(&i, &s1, 1); secp256k1_fe_addX(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_varX(&h)) {
        if (secp256k1_fe_normalizes_to_zero_varX(&i)) {
            secp256k1_gej_double_varX(r, a, rzr);
        } else {
            if (rzr != NULL) {
                secp256k1_fe_set_intX(rzr, 0);
            }
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqrX(&i2, &i);
    secp256k1_fe_sqrX(&h2, &h);
    secp256k1_fe_mulX(&h3, &h, &h2);
    if (rzr != NULL) {
        *rzr = h;
    }
    secp256k1_fe_mulX(&r->z, &a->z, &h);
    secp256k1_fe_mulX(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_intX(&r->x, 2); secp256k1_fe_addX(&r->x, &h3); secp256k1_fe_negateX(&r->x, &r->x, 3); secp256k1_fe_addX(&r->x, &i2);
    secp256k1_fe_negateX(&r->y, &r->x, 5); secp256k1_fe_addX(&r->y, &t); secp256k1_fe_mulX(&r->y, &r->y, &i);
    secp256k1_fe_mulX(&h3, &h3, &s1); secp256k1_fe_negateX(&h3, &h3, 1);
    secp256k1_fe_addX(&r->y, &h3);
}

static void secp256k1_ecmult_odd_multiples_tableX(int n, secp256k1_gejX *prej, secp256k1_feX *zr, const secp256k1_gejX *a) {
    secp256k1_gejX d;
    secp256k1_geX a_ge, d_ge;
    int i;

    secp256k1_gej_double_varX(&d, a, NULL);

    d_ge.x = d.x;
    d_ge.y = d.y;
    d_ge.infinity = 0;

    secp256k1_ge_set_gej_zinvX(&a_ge, a, &d.z);
    prej[0].x = a_ge.x;
    prej[0].y = a_ge.y;
    prej[0].z = a->z;
    prej[0].infinity = 0;

    zr[0] = d.z;
    for (i = 1; i < n; i++) {
        secp256k1_gej_add_ge_varX(&prej[i], &prej[i-1], &d_ge, &zr[i]);
    }

    /*
     * Each point in 'prej' has a z coordinate too small by a factor of 'd.z'. Only
     * the final point's z coordinate is actually used though, so just update that.
     */
    secp256k1_fe_mulX(&prej[n-1].z, &prej[n-1].z, &d.z);
}

static void secp256k1_fe_normalize_varX(secp256k1_feX *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    uint64_t m;
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL)
        & (t0 >= 0xFFFFEFFFFFC2FULL));

    if (x) {
        t0 += 0x1000003D1ULL;
        t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
        t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
        t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
        t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

        /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */

        /* Mask off the possible multiple of 2^256 from the final reduction */
        t4 &= 0x0FFFFFFFFFFFFULL;
    }

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verifyX(r);
}

static void secp256k1_gej_rescaleX(secp256k1_gejX *r, const secp256k1_feX *s) {
    /* Operations: 4 mul, 1 sqr */
    secp256k1_feX zz;
    secp256k1_fe_sqrX(&zz, s);
    secp256k1_fe_mulX(&r->x, &r->x, &zz);                /* r->x *= s^2 */
    secp256k1_fe_mulX(&r->y, &r->y, &zz);
    secp256k1_fe_mulX(&r->y, &r->y, s);                  /* r->y *= s^3 */
    secp256k1_fe_mulX(&r->z, &r->z, s);                  /* r->z *= s   */
}

static void secp256k1_ge_globalz_set_table_gejX(size_t len, secp256k1_geX *r, secp256k1_feX *globalz, const secp256k1_gejX *a, const secp256k1_feX *zr) {
    size_t i = len - 1;
    secp256k1_feX zs;

    if (len > 0) {
        /* The z of the final point gives us the "global Z" for the table. */
        r[i].x = a[i].x;
        r[i].y = a[i].y;
        /* Ensure all y values are in weak normal form for fast negation of points */
        secp256k1_fe_normalize_weakX(&r[i].y);
        *globalz = a[i].z;
        r[i].infinity = 0;
        zs = zr[i];

        /* Work our way backwards, using the z-ratios to scale the x/y values. */
        while (i > 0) {
            if (i != len - 1) {
                secp256k1_fe_mulX(&zs, &zs, &zr[i]);
            }
            i--;
            secp256k1_ge_set_gej_zinvX(&r[i], &a[i], &zs);
        }
    }
}

static void secp256k1_gej_set_infinityX(secp256k1_gejX *r) {
    r->infinity = 1;
    secp256k1_fe_clearX(&r->x);
    secp256k1_fe_clearX(&r->y);
    secp256k1_fe_clearX(&r->z);
}

/*
static void secp256k1_gej_add_zinv_varX_GPU(secp256k1_gejX *r, const secp256k1_gejX *a, const secp256k1_geX *b, const secp256k1_feX *bzinv) {
	secp256k1_gejX res;
	secp256k1_gej_add_zinv_varX_CPU(&res, a, b, bzinv);
	const int LIST_SIZE = 4;
    FILE *fp;
    char *source_str;
    size_t source_size;
    fp = fopen("src/kernels.cl", "r");
    if (!fp) {
        fprintf(stderr, "Failed to load kernel.\n");
        exit(1);
    }
    source_str = (char*)malloc(MAX_SOURCE_SIZE);
    source_size = fread( source_str, 1, MAX_SOURCE_SIZE, fp);
    fclose( fp );
 
    cl_platform_id platform_id = NULL;
    cl_device_id device_id = NULL;   
    cl_uint ret_num_devices;
    cl_uint ret_num_platforms;
    cl_int ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
    ret = clGetDeviceIDs( platform_id, CL_DEVICE_TYPE_GPU, 1, 
            &device_id, &ret_num_devices);
 
    cl_context context = clCreateContext( NULL, 1, &device_id, NULL, NULL, &ret);
 
    cl_command_queue command_queue = clCreateCommandQueue(context, device_id, 0, &ret);
 
    cl_mem a_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        sizeof(secp256k1_contextX), NULL, &ret);
    
    cl_mem b_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        sizeof(secp256k1_ecdsa_signatureX), NULL, &ret);
	
	cl_mem c_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        32 * sizeof(char), NULL, &ret);
    
    cl_mem d_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        sizeof(secp256k1_pubkeyX), NULL, &ret);
	
	cl_mem e_mem_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 
                        sizeof(int), NULL, &ret);
						
	cl_mem f_mem_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 
                        sizeof(secp256k1_gejX), NULL, &ret);

 
    ret = clEnqueueWriteBuffer(command_queue, a_mem_obj, CL_TRUE, 0,
                      sizeof(secp256k1_contextX), ctx, 0, NULL, NULL);
	ret = clEnqueueWriteBuffer(command_queue, b_mem_obj, CL_TRUE, 0,
                      sizeof(secp256k1_ecdsa_signatureX), sig, 0, NULL, NULL);
	ret = clEnqueueWriteBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
                      32*sizeof(char), msg32, 0, NULL, NULL);
	ret = clEnqueueWriteBuffer(command_queue, d_mem_obj, CL_TRUE, 0,
                      sizeof(secp256k1_pubkeyX), pubkey, 0, NULL, NULL);
					  
    cl_program program = clCreateProgramWithSource(context, 1, 
            (const char **)&source_str, (const size_t *)&source_size, &ret);
 
    ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
 
    cl_kernel kernel = clCreateKernel(program, "secp256k1_ecdsa_verifyX", &ret);
 
    ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&a_mem_obj);
    ret = clSetKernelArg(kernel, 1, sizeof(cl_mem), (void *)&b_mem_obj);
	ret = clSetKernelArg(kernel, 2, sizeof(cl_mem), (void *)&c_mem_obj);
    ret = clSetKernelArg(kernel, 3, sizeof(cl_mem), (void *)&d_mem_obj);
	ret = clSetKernelArg(kernel, 4, sizeof(cl_mem), (void *)&e_mem_obj);
	ret = clSetKernelArg(kernel, 5, sizeof(cl_mem), (void *)&f_mem_obj);
 
    size_t global_item_size = 1; 
    size_t local_item_size = 1; 
    ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, 
            &global_item_size, &local_item_size, 0, NULL, NULL);
 
    int *res = (int*)malloc(sizeof(int));
	secp256k1_gejX *pubGPU = (secp256k1_gejX*)malloc(sizeof(secp256k1_gejX));
	
    ret = clEnqueueReadBuffer(command_queue, e_mem_obj, CL_TRUE, 0, 
                        sizeof(int), res, 0, NULL, NULL);
						
	ret = clEnqueueReadBuffer(command_queue, f_mem_obj, CL_TRUE, 0, 
                        sizeof(secp256k1_gejX), pubGPU, 0, NULL, NULL);
						
	
	size_t log_size;
    clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
    char *log = (char *) malloc(log_size);
    clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
	printf("\%s\n", log);
	
	ret = clFlush(command_queue);
    ret = clFinish(command_queue);
    ret = clReleaseKernel(kernel);
    ret = clReleaseProgram(program);
    ret = clReleaseMemObject(a_mem_obj);
    ret = clReleaseMemObject(b_mem_obj);
    ret = clReleaseCommandQueue(command_queue);
    ret = clReleaseContext(context);
	
	
}*/

static void secp256k1_fe_mulX_z(secp256k1_feX *r, secp256k1_feX *a, const secp256k1_feX * SECP256K1_RESTRICT b) {

	secp256k1_fe_verifyX(a);
    secp256k1_fe_verifyX(b);
	uint64_t rn[5];
    secp256k1_fe_mul_innerX_z(r, a->n, b->n);
	/*printf("\nOOO %lu", rn[0]);*/
    r->magnitude = 1;
    r->normalized = 0;
}


static void secp256k1_gej_add_zinv_varX(secp256k1_gejX *r, const secp256k1_gejX *a, const secp256k1_geX *b, const secp256k1_feX *bzinv) {
    /* 9 mul, 3 sqr, 4 normalize, 12 mul_int/add/negate */
    secp256k1_feX az, z12, u1, u2, s1, s2, h, i, i2, h2, h3, t;
    if (b->infinity) {
        *r = *a;
        return;
    }
	
	
    if (a->infinity) {
        secp256k1_feX bzinv2, bzinv3;
        r->infinity = b->infinity;
        secp256k1_fe_sqrX(&bzinv2, bzinv);
        secp256k1_fe_mulX(&bzinv3, &bzinv2, bzinv);
        secp256k1_fe_mulX(&r->x, &b->x, &bzinv2);
        secp256k1_fe_mulX(&r->y, &b->y, &bzinv3);
        secp256k1_fe_set_intX(&r->z, 1);
		
        return;
    }
    r->infinity = 0;

    secp256k1_fe_mulX(&az, &a->z, bzinv);

    secp256k1_fe_sqrX(&z12, &az);
    u1 = a->x; secp256k1_fe_normalize_weakX(&u1);
    secp256k1_fe_mulX(&u2, &b->x, &z12);
    s1 = a->y; secp256k1_fe_normalize_weakX(&s1);
    secp256k1_fe_mulX(&s2, &b->y, &z12); secp256k1_fe_mulX(&s2, &s2, &az);
    secp256k1_fe_negateX(&h, &u1, 1); secp256k1_fe_addX(&h, &u2);
    secp256k1_fe_negateX(&i, &s1, 1); secp256k1_fe_addX(&i, &s2);
    if (secp256k1_fe_normalizes_to_zero_varX(&h)) {
        if (secp256k1_fe_normalizes_to_zero_varX(&i)) {
            secp256k1_gej_double_varX(r, a, NULL);
        } else {
            r->infinity = 1;
        }
        return;
    }
    secp256k1_fe_sqrX(&i2, &i);
    secp256k1_fe_sqrX(&h2, &h);
    secp256k1_fe_mulX(&h3, &h, &h2);
    r->z = a->z; secp256k1_fe_mulX(&r->z, &r->z, &h);
    secp256k1_fe_mulX(&t, &u1, &h2);
    r->x = t; secp256k1_fe_mul_intX(&r->x, 2); secp256k1_fe_addX(&r->x, &h3); secp256k1_fe_negateX(&r->x, &r->x, 3); secp256k1_fe_addX(&r->x, &i2);
    secp256k1_fe_negateX(&r->y, &r->x, 5); secp256k1_fe_addX(&r->y, &t); secp256k1_fe_mulX(&r->y, &r->y, &i);
    secp256k1_fe_mulX(&h3, &h3, &s1); secp256k1_fe_negateX(&h3, &h3, 1);
    secp256k1_fe_addX(&r->y, &h3);
}

void secp256k1_ecmult_strauss_wnafX(const secp256k1_ecmult_contextX *ctx, const struct secp256k1_strauss_stateX *state, secp256k1_gejX *r, int num, const secp256k1_gejX *a, const secp256k1_scalarX *na, const secp256k1_scalarX *ng) {
    secp256k1_geX tmpa;
    secp256k1_feX Z;
    int wnaf_ng[256];
    int bits_ng = 0;
    int i;
    int bits = 0;
    int np;
    int no = 0;

    for (np = 0; np < num; ++np) {
        if (secp256k1_scalar_is_zeroX(&na[np]) || secp256k1_gej_is_infinityX(&a[np])) {
            continue;
        }
        state->ps[no].input_pos = np;
        state->ps[no].bits_na     = secp256k1_ecmult_wnafX(state->ps[no].wnaf_na,     256, &na[np],      WINDOW_A);
        if (state->ps[no].bits_na > bits) {
            bits = state->ps[no].bits_na;
        }
        ++no;
    }

    if (no > 0) {
        secp256k1_ecmult_odd_multiples_tableX(ECMULT_TABLE_SIZE(WINDOW_A), state->prej, state->zr, &a[state->ps[0].input_pos]);
        for (np = 1; np < no; ++np) {
            secp256k1_gejX tmp = a[state->ps[np].input_pos];
            secp256k1_fe_normalize_varX(&(state->prej[(np - 1) * ECMULT_TABLE_SIZE(WINDOW_A) + ECMULT_TABLE_SIZE(WINDOW_A) - 1].z));
            secp256k1_gej_rescaleX(&tmp, &(state->prej[(np - 1) * ECMULT_TABLE_SIZE(WINDOW_A) + ECMULT_TABLE_SIZE(WINDOW_A) - 1].z));
            secp256k1_ecmult_odd_multiples_tableX(ECMULT_TABLE_SIZE(WINDOW_A), state->prej + np * ECMULT_TABLE_SIZE(WINDOW_A), state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), &tmp);
            secp256k1_fe_mulX(state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), state->zr + np * ECMULT_TABLE_SIZE(WINDOW_A), &(a[state->ps[np].input_pos].z));
        }
        secp256k1_ge_globalz_set_table_gejX(ECMULT_TABLE_SIZE(WINDOW_A) * no, state->pre_a, &Z, state->prej, state->zr);
    } else {
        secp256k1_fe_set_intX(&Z, 1);
    }

    if (ng) {
        bits_ng     = secp256k1_ecmult_wnafX(wnaf_ng,     256, ng,      WINDOW_G);
        if (bits_ng > bits) {
            bits = bits_ng;
        }
    }

    secp256k1_gej_set_infinityX(r);
	
    for (i = bits - 1; i >= 0; i--) {
        int n;
        secp256k1_gej_double_varX(r, r, NULL);
        for (np = 0; np < no; ++np) {
            if (i < state->ps[np].bits_na && (n = state->ps[np].wnaf_na[i])) {
                ECMULT_TABLE_GET_GE(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                secp256k1_gej_add_ge_varX(r, r, &tmpa, NULL);
            }
        }
       
        if (i < bits_ng && (n = wnaf_ng[i])) {
			/*printf("\ni %d ", i);
			printf("A C x %ul ", &(*ctx->pre_g)[i].x.n[0]);
			printf("A C y %ul ", &(*ctx->pre_g)[i].y.n[0]);*/
            ECMULT_TABLE_GET_GE_STORAGE(&tmpa, *ctx->pre_g, n, WINDOW_G);
			secp256k1_gej_add_zinv_varX(r, r, &tmpa, &Z);
			
        }
    }
    if (!r->infinity) {
        secp256k1_fe_mulX(&r->z, &r->z, &Z);
    }
}

static void secp256k1_scalar_get_b32X(unsigned char *bin, const secp256k1_scalarX* a) {
    bin[0] = a->d[3] >> 56; bin[1] = a->d[3] >> 48; bin[2] = a->d[3] >> 40; bin[3] = a->d[3] >> 32; bin[4] = a->d[3] >> 24; bin[5] = a->d[3] >> 16; bin[6] = a->d[3] >> 8; bin[7] = a->d[3];
    bin[8] = a->d[2] >> 56; bin[9] = a->d[2] >> 48; bin[10] = a->d[2] >> 40; bin[11] = a->d[2] >> 32; bin[12] = a->d[2] >> 24; bin[13] = a->d[2] >> 16; bin[14] = a->d[2] >> 8; bin[15] = a->d[2];
    bin[16] = a->d[1] >> 56; bin[17] = a->d[1] >> 48; bin[18] = a->d[1] >> 40; bin[19] = a->d[1] >> 32; bin[20] = a->d[1] >> 24; bin[21] = a->d[1] >> 16; bin[22] = a->d[1] >> 8; bin[23] = a->d[1];
    bin[24] = a->d[0] >> 56; bin[25] = a->d[0] >> 48; bin[26] = a->d[0] >> 40; bin[27] = a->d[0] >> 32; bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
}

static int secp256k1_fe_set_b32X(secp256k1_feX *r, const unsigned char *a) {
	int i;
    r->n[0] = r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
    for (i=0; i<32; i++) {
        int j;
        for (j=0; j<2; j++) {
            int limb = (8*i+4*j)/52;
            int shift = (8*i+4*j)%52;
            r->n[limb] |= (uint64_t)((a[31-i] >> (4*j)) & 0xF) << shift;
        }
    }
    if (r->n[4] == 0x0FFFFFFFFFFFFULL && (r->n[3] & r->n[2] & r->n[1]) == 0xFFFFFFFFFFFFFULL && r->n[0] >= 0xFFFFEFFFFFC2FULL) {
        return 0;
    }
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verifyX(r);
    return 1;
}

static int secp256k1_gej_eq_x_varX(const secp256k1_feX *x, const secp256k1_gejX *a) {
    secp256k1_feX r, r2;
    secp256k1_fe_sqrX(&r, &a->z); secp256k1_fe_mulX(&r, &r, x);
    r2 = a->x; secp256k1_fe_normalize_weakX(&r2);
    return secp256k1_fe_equal_varX(&r, &r2);
}

int secp256k1_fe_equal_varX(const secp256k1_feX *a, const secp256k1_feX *b) {
    secp256k1_feX na;
    secp256k1_fe_negateX(&na, a, 1);
    secp256k1_fe_addX(&na, b);
    return secp256k1_fe_normalizes_to_zero_varX(&na);
}

static int secp256k1_fe_cmp_varX(const secp256k1_feX *a, const secp256k1_feX *b) {
    int i;
    secp256k1_fe_verifyX(a);
    secp256k1_fe_verifyX(b);
    for (i = 4; i >= 0; i--) {
        if (a->n[i] > b->n[i]) {
            return 1;
        }
        if (a->n[i] < b->n[i]) {
            return -1;
        }
    }
    return 0;
}

static void secp256k1_scalar_set_b32X(secp256k1_scalarX *r, const unsigned char *b32, int *overflow) {
    int over;
    r->d[0] = (uint64_t)b32[31] | (uint64_t)b32[30] << 8 | (uint64_t)b32[29] << 16 | (uint64_t)b32[28] << 24 | (uint64_t)b32[27] << 32 | (uint64_t)b32[26] << 40 | (uint64_t)b32[25] << 48 | (uint64_t)b32[24] << 56;
    r->d[1] = (uint64_t)b32[23] | (uint64_t)b32[22] << 8 | (uint64_t)b32[21] << 16 | (uint64_t)b32[20] << 24 | (uint64_t)b32[19] << 32 | (uint64_t)b32[18] << 40 | (uint64_t)b32[17] << 48 | (uint64_t)b32[16] << 56;
    r->d[2] = (uint64_t)b32[15] | (uint64_t)b32[14] << 8 | (uint64_t)b32[13] << 16 | (uint64_t)b32[12] << 24 | (uint64_t)b32[11] << 32 | (uint64_t)b32[10] << 40 | (uint64_t)b32[9] << 48 | (uint64_t)b32[8] << 56;
    r->d[3] = (uint64_t)b32[7] | (uint64_t)b32[6] << 8 | (uint64_t)b32[5] << 16 | (uint64_t)b32[4] << 24 | (uint64_t)b32[3] << 32 | (uint64_t)b32[2] << 40 | (uint64_t)b32[1] << 48 | (uint64_t)b32[0] << 56;
    over = secp256k1_scalar_reduceX(r, secp256k1_scalar_check_overflowX(r));
    if (overflow) {
        *overflow = over;
    }
}


void memcpyX(void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  while (len--)
    *d++ = *s++;
  return dest;
}

static void secp256k1_ecdsa_signature_loadX(const secp256k1_contextX* ctx, secp256k1_scalarX* r, secp256k1_scalarX* s, secp256k1_ecdsa_signatureX* sig) {
    (void)ctx;
    if (sizeof(secp256k1_scalarX) == 32) {
        memcpyX(r, &sig->data[0], 32);
        memcpyX(s, &sig->data[32], 32);
    } else {
        secp256k1_scalar_set_b32X(r, &sig->data[0], NULL);
        secp256k1_scalar_set_b32X(s, &sig->data[32], NULL);
    }
}

static void secp256k1_ge_set_xyX(secp256k1_geX *r, const secp256k1_feX *x, const secp256k1_feX *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}

static int secp256k1_pubkey_loadX(const secp256k1_contextX* ctx, secp256k1_geX* ge, const secp256k1_pubkeyX* pubkey) {
    if (sizeof(secp256k1_ge_storageX) == 64) {
        /* When the secp256k1_ge_storageX type is exactly 64 byte, use its
         * representation inside secp256k1_pubkeyX, as conversion is very fast.
         * Note that secp256k1_pubkey_save must use the same representation. */
        secp256k1_ge_storageX s;
        memcpy(&s, &pubkey->data[0], 64);
        secp256k1_ge_from_storageX(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        secp256k1_feX x, y;
        secp256k1_fe_set_b32X(&x, pubkey->data);
        secp256k1_fe_set_b32X(&y, pubkey->data + 32);
        secp256k1_ge_set_xyX(ge, &x, &y);
    }
    return 1;
}

static int secp256k1_ecdsa_sig_verifyX(const secp256k1_ecmult_contextX *ctx, const secp256k1_scalarX *sigr, const secp256k1_scalarX *sigs, const secp256k1_geX *pubkey, const secp256k1_scalarX *message) {
    unsigned char c[32];
    secp256k1_scalarX sn, u1, u2;
    secp256k1_feX xr;
    secp256k1_gejX pubkeyj;
    secp256k1_gejX pr;

    if (secp256k1_scalar_is_zeroX(sigr) || secp256k1_scalar_is_zeroX(sigs)) {
        return 0;
    }
    secp256k1_scalar_inverse_varX(&sn, sigs);
    secp256k1_scalar_mulX(&u1, &sn, message);
    secp256k1_scalar_mulX(&u2, &sn, sigr);
    secp256k1_gej_set_geX(&pubkeyj, pubkey);
    secp256k1_ecmultX(ctx, &pr, &pubkeyj, &u2, &u1);
    if (secp256k1_gej_is_infinityX(&pr)) {
        return 0;
    }
    secp256k1_scalar_get_b32X(c, sigr);
    secp256k1_fe_set_b32X(&xr, c);
    if (secp256k1_gej_eq_x_varX(&xr, &pr)) {
        return 1;
    }
    if (secp256k1_fe_cmp_varX(&xr, &secp256k1_ecdsa_const_p_minus_orderX) >= 0) {
        return 0;
    }
    secp256k1_fe_addX(&xr, &secp256k1_ecdsa_const_order_as_feX);
    if (secp256k1_gej_eq_x_varX(&xr, &pr)) {
        return 1;
    }
    return 0;
}

static secp256k1_gejX secp256k1_ecdsa_sig_verifyXX(const secp256k1_ecmult_contextX *ctx, const secp256k1_scalarX *sigr, const secp256k1_scalarX *sigs, const secp256k1_geX *pubkey, const secp256k1_scalarX *message) {
    unsigned char c[32];
    secp256k1_scalarX sn, u1, u2;
    secp256k1_feX xr;
    secp256k1_gejX pubkeyj;
    secp256k1_gejX pr;

    /*if (secp256k1_scalar_is_zeroX(sigr) || secp256k1_scalar_is_zeroX(sigs)) {
        return 0;
    }*/
    secp256k1_scalar_inverse_varX(&sn, sigs);
    secp256k1_scalar_mulX(&u1, &sn, message);
    secp256k1_scalar_mulX(&u2, &sn, sigr);
    secp256k1_gej_set_geX(&pubkeyj, pubkey);
    secp256k1_ecmultX(ctx, &pr, &pubkeyj, &u2, &u1);
	return pr;
    /*if (secp256k1_gej_is_infinityX(&pr)) {
        return 0;
    }
    secp256k1_scalar_get_b32X(c, sigr);
    secp256k1_fe_set_b32X(&xr, c);

    if (secp256k1_gej_eq_x_varX(&xr, &pr)) {
        return 1;
    }
    if (secp256k1_fe_cmp_varX(&xr, &secp256k1_ecdsa_const_p_minus_orderX) >= 0) {
        return 0;
    }
    secp256k1_fe_addX(&xr, &secp256k1_ecdsa_const_order_as_feX);
    if (secp256k1_gej_eq_x_varX(&xr, &pr)) {
        return 1;
    }
    return 0;*/
}

int secp256k1_ecdsa_verifyX(const secp256k1_contextX* ctx, const secp256k1_ecdsa_signatureX *sig, const unsigned char *msg32, const secp256k1_pubkeyX *pubkey) {
	
	secp256k1_geX q;
	secp256k1_gejX pubj;
	secp256k1_scalarX r1, s1;
    secp256k1_scalarX m;
    secp256k1_scalar_set_b32(&m, msg32, NULL);
    secp256k1_ecdsa_signature_load(ctx, &r1, &s1, sig);
	return (secp256k1_pubkey_load(ctx, &q, pubkey) && secp256k1_ecdsa_sig_verifyX(&ctx->ecmult_ctx, &r1, &s1, &q, &m));

	
	/*
	const int LIST_SIZE = 4;
    FILE *fp;
    char *source_str;
    size_t source_size;
    fp = fopen("src/kernels.cl", "r");
    if (!fp) {
        fprintf(stderr, "Failed to load kernel.\n");
        exit(1);
    }
    source_str = (char*)malloc(MAX_SOURCE_SIZE);
    source_size = fread( source_str, 1, MAX_SOURCE_SIZE, fp);
    fclose( fp );
 
    cl_platform_id platform_id = NULL;
    cl_device_id device_id = NULL;   
    cl_uint ret_num_devices;
    cl_uint ret_num_platforms;
    cl_int ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
    ret = clGetDeviceIDs( platform_id, CL_DEVICE_TYPE_GPU, 1, 
            &device_id, &ret_num_devices);
 
    cl_context context = clCreateContext( NULL, 1, &device_id, NULL, NULL, &ret);
 
    cl_command_queue command_queue = clCreateCommandQueue(context, device_id, 0, &ret);
 
    cl_mem a_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        sizeof(secp256k1_contextX), NULL, &ret);
    
    cl_mem b_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        sizeof(secp256k1_ecdsa_signatureX), NULL, &ret);
	
	cl_mem c_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        32 * sizeof(char), NULL, &ret);
    
    cl_mem d_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        sizeof(secp256k1_pubkeyX), NULL, &ret);
	
	cl_mem e_mem_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 
                        sizeof(int), NULL, &ret);
						
	cl_mem f_mem_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 
                        sizeof(secp256k1_gejX), NULL, &ret);

 
    ret = clEnqueueWriteBuffer(command_queue, a_mem_obj, CL_TRUE, 0,
                      sizeof(secp256k1_contextX), ctx, 0, NULL, NULL);
	ret = clEnqueueWriteBuffer(command_queue, b_mem_obj, CL_TRUE, 0,
                      sizeof(secp256k1_ecdsa_signatureX), sig, 0, NULL, NULL);
	ret = clEnqueueWriteBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
                      32*sizeof(char), msg32, 0, NULL, NULL);
	ret = clEnqueueWriteBuffer(command_queue, d_mem_obj, CL_TRUE, 0,
                      sizeof(secp256k1_pubkeyX), pubkey, 0, NULL, NULL);
					  
    cl_program program = clCreateProgramWithSource(context, 1, 
            (const char **)&source_str, (const size_t *)&source_size, &ret);
 
    ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
 
    cl_kernel kernel = clCreateKernel(program, "secp256k1_ecdsa_verifyX", &ret);
 
    ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&a_mem_obj);
    ret = clSetKernelArg(kernel, 1, sizeof(cl_mem), (void *)&b_mem_obj);
	ret = clSetKernelArg(kernel, 2, sizeof(cl_mem), (void *)&c_mem_obj);
    ret = clSetKernelArg(kernel, 3, sizeof(cl_mem), (void *)&d_mem_obj);
	ret = clSetKernelArg(kernel, 4, sizeof(cl_mem), (void *)&e_mem_obj);
	ret = clSetKernelArg(kernel, 5, sizeof(cl_mem), (void *)&f_mem_obj);
 
    size_t global_item_size = 1; 
    size_t local_item_size = 1; 
    ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, 
            &global_item_size, &local_item_size, 0, NULL, NULL);
 
    int *res = (int*)malloc(sizeof(int));
    ret = clEnqueueReadBuffer(command_queue, e_mem_obj, CL_TRUE, 0, 
                        sizeof(int), res, 0, NULL, NULL);
						
	
	size_t log_size;
    clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
    char *log = (char *) malloc(log_size);
    clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
	printf("\%s\n", log);
	
	secp256k1_geX q;
	secp256k1_gejX pubj;
	secp256k1_scalarX r1, s1;
    secp256k1_scalarX m;
    secp256k1_scalar_set_b32(&m, msg32, NULL);
    secp256k1_ecdsa_signature_load(ctx, &r1, &s1, sig);
	int tmp = (secp256k1_pubkey_load(ctx, &q, pubkey) && secp256k1_ecdsa_sig_verifyX(&ctx->ecmult_ctx, &r1, &s1, &q, &m));

	printf("\nresults: %d %d\n", tmp, *res);
	
	char c;
	scanf("%c", &c);
    ret = clFlush(command_queue);
    ret = clFinish(command_queue);
    ret = clReleaseKernel(kernel);
    ret = clReleaseProgram(program);
    ret = clReleaseMemObject(a_mem_obj);
    ret = clReleaseMemObject(b_mem_obj);
    ret = clReleaseCommandQueue(command_queue);
    ret = clReleaseContext(context);
	*/
	return 1;
}




int secp256k1_ecdsa_verify_arr(const secp256k1_contextX* ctx, secp256k1_ecdsa_signatureX *sig, const unsigned char *msg32, const secp256k1_pubkeyX *pubkey) {
	
	const int LIST_SIZE = NUM_OF_SIGS;
    FILE *fp;
    char *source_str;
    size_t source_size;
    fp = fopen("src/k.cl", "r");
    if (!fp) {
        fprintf(stderr, "Failed to load kernel.\n");
        exit(1);
    }
    source_str = (char*)malloc(MAX_SOURCE_SIZE);
    source_size = fread( source_str, 1, MAX_SOURCE_SIZE, fp);
    fclose( fp );
	
    cl_platform_id platform_id = NULL;
    cl_device_id device_id = NULL;   
    cl_uint ret_num_devices;
    cl_uint ret_num_platforms;
    cl_int ret = clGetPlatformIDs(1, &platform_id, &ret_num_platforms);
    ret = clGetDeviceIDs( platform_id, CL_DEVICE_TYPE_GPU, 1, 
            &device_id, &ret_num_devices);
 
	secp256k1_ge_storageX* arr = (secp256k1_ge_storageX*)malloc(8192*sizeof(secp256k1_ge_storageX));
	int idx, nnn;
	for(idx = 0; idx < 8192; idx++ )
	{
		for(nnn = 0; nnn < 4; nnn++ )
		{
			arr[idx].x.n[nnn] = (*ctx->ecmult_ctx.pre_g)[idx].x.n[nnn];
			arr[idx].y.n[nnn] = (*ctx->ecmult_ctx.pre_g)[idx].y.n[nnn];
		}
	}


    cl_context context = clCreateContext( NULL, 1, &device_id, NULL, NULL, &ret);
 
    cl_command_queue command_queue = clCreateCommandQueue(context, device_id, 0, &ret);
 
    cl_mem a_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        8192*sizeof(secp256k1_ge_storageX), NULL, &ret);
    
    cl_mem b_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        LIST_SIZE*sizeof(secp256k1_ecdsa_signatureX), NULL, &ret);
	
	cl_mem c_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        32 * sizeof(char), NULL, &ret);
    
    cl_mem d_mem_obj = clCreateBuffer(context, CL_MEM_READ_ONLY, 
                        sizeof(secp256k1_pubkeyX), NULL, &ret);
	cl_mem e_mem_obj = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 
                        LIST_SIZE*sizeof(int), NULL, &ret);
						
    ret = clEnqueueWriteBuffer(command_queue, a_mem_obj, CL_TRUE, 0,
                      8192*sizeof(secp256k1_ge_storageX), arr, 0, NULL, NULL);
	ret = clEnqueueWriteBuffer(command_queue, b_mem_obj, CL_TRUE, 0,
                      LIST_SIZE*sizeof(secp256k1_ecdsa_signatureX), sig, 0, NULL, NULL); 
	ret = clEnqueueWriteBuffer(command_queue, c_mem_obj, CL_TRUE, 0,
                      32*sizeof(char), msg32, 0, NULL, NULL);
	ret = clEnqueueWriteBuffer(command_queue, d_mem_obj, CL_TRUE, 0,
                      sizeof(secp256k1_pubkeyX), pubkey, 0, NULL, NULL);
			  
    cl_program program = clCreateProgramWithSource(context, 1, 
            (const char **)&source_str, (const size_t *)&source_size, &ret);
	
    ret = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
 
    cl_kernel kernel = clCreateKernel(program, "secp256k1_ecdsa_verifyX", &ret);
    ret = clSetKernelArg(kernel, 0, sizeof(cl_mem), (void *)&a_mem_obj);
    ret = clSetKernelArg(kernel, 1, sizeof(cl_mem), (void *)&b_mem_obj);
	ret = clSetKernelArg(kernel, 2, sizeof(cl_mem), (void *)&c_mem_obj);
    ret = clSetKernelArg(kernel, 3, sizeof(cl_mem), (void *)&d_mem_obj);
	ret = clSetKernelArg(kernel, 4, sizeof(cl_mem), (void *)&e_mem_obj);
 
    size_t global_item_size = LIST_SIZE; 
    size_t local_item_size = 1;
	if(LIST_SIZE > 100)
	{
		local_item_size = 40;
	}
    ret = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL,
            &global_item_size, &local_item_size, 0, NULL, NULL);
 
    int *res = (int*)malloc(LIST_SIZE*sizeof(int));
    ret = clEnqueueReadBuffer(command_queue, e_mem_obj, CL_TRUE, 0, 
                        LIST_SIZE*sizeof(int), res, 0, NULL, NULL);
						
	
	size_t log_size;
    clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
    char *log = (char *) malloc(log_size);
    clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, log_size, log, NULL);
	printf("\%s\n", log);
	
	secp256k1_geX q;
	secp256k1_gejX pubj;
	secp256k1_scalarX r1, s1;
    secp256k1_scalarX m;
    secp256k1_scalar_set_b32(&m, msg32, NULL);
    secp256k1_ecdsa_signature_load(ctx, &r1, &s1, sig);
	int tmp = (secp256k1_pubkey_load(ctx, &q, pubkey) && secp256k1_ecdsa_sig_verifyX(&ctx->ecmult_ctx, &r1, &s1, &q, &m));
	
	int k;
	printf("\n# CPU GPU\n");
	for(k=0;k<LIST_SIZE;k++)
	{
		printf("%d ", k);
		printf(" %d   %d\n", tmp, res[k]);
	}
	printf("\n# CPU GPU\n");
	
	char c;
	/*scanf("%c", &c);*/
    ret = clFlush(command_queue);
    ret = clReleaseKernel(kernel);
    ret = clReleaseProgram(program);
    ret = clReleaseMemObject(a_mem_obj);
    ret = clReleaseMemObject(b_mem_obj);
    ret = clReleaseCommandQueue(command_queue);
    ret = clReleaseContext(context);
	
	return 1;
}




void random_field_element_test(secp256k1_fe *fe) {
    do {
        unsigned char b32[32];
        secp256k1_rand256_test(b32);
        if (secp256k1_fe_set_b32(fe, b32)) {
            break;
        }
    } while(1);
}

void random_field_element_magnitude(secp256k1_fe *fe) {
    secp256k1_fe zero;
    int n = secp256k1_rand32() % 9;
    secp256k1_fe_normalize(fe);
    if (n == 0) {
        return;
    }
    secp256k1_fe_clear(&zero);
    secp256k1_fe_negate(&zero, &zero, 0);
    secp256k1_fe_mul_int(&zero, n - 1);
    secp256k1_fe_add(fe, &zero);
    VERIFY_CHECK(fe->magnitude == n);
}

void random_group_element_test(secp256k1_ge *ge) {
    secp256k1_fe fe;
    do {
        random_field_element_test(&fe);
        if (secp256k1_ge_set_xo_var(ge, &fe, secp256k1_rand32() & 1)) {
            secp256k1_fe_normalize(&ge->y);
            break;
        }
    } while(1);
}

void random_group_element_jacobian_test(secp256k1_gej *gej, const secp256k1_ge *ge) {
    secp256k1_fe z2, z3;
    do {
        random_field_element_test(&gej->z);
        if (!secp256k1_fe_is_zero(&gej->z)) {
            break;
        }
    } while(1);
    secp256k1_fe_sqr(&z2, &gej->z);
    secp256k1_fe_mul(&z3, &z2, &gej->z);
    secp256k1_fe_mul(&gej->x, &ge->x, &z2);
    secp256k1_fe_mul(&gej->y, &ge->y, &z3);
    gej->infinity = ge->infinity;
}

void random_scalar_order_test(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        secp256k1_rand256_test(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}

void random_scalar_order(secp256k1_scalar *num) {
    do {
        unsigned char b32[32];
        int overflow = 0;
        secp256k1_rand256(b32);
        secp256k1_scalar_set_b32(num, b32, &overflow);
        if (overflow || secp256k1_scalar_is_zero(num)) {
            continue;
        }
        break;
    } while(1);
}

void run_context_tests(void) {
    secp256k1_context *none = secp256k1_context_create(0);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    secp256k1_gej pubj;
    secp256k1_ge pub;
    secp256k1_scalar msg, key, nonce;
    secp256k1_scalar sigr, sigs;

    /*** clone and destroy all of them to make sure cloning was complete ***/
    {
        secp256k1_context *ctx_tmp;

        ctx_tmp = none; none = secp256k1_context_clone(none); secp256k1_context_destroy(ctx_tmp);
        ctx_tmp = sign; sign = secp256k1_context_clone(sign); secp256k1_context_destroy(ctx_tmp);
        ctx_tmp = vrfy; vrfy = secp256k1_context_clone(vrfy); secp256k1_context_destroy(ctx_tmp);
        ctx_tmp = both; both = secp256k1_context_clone(both); secp256k1_context_destroy(ctx_tmp);
    }

    /*** attempt to use them ***/
    random_scalar_order_test(&msg);
    random_scalar_order_test(&key);
    secp256k1_ecmult_gen(&both->ecmult_gen_ctx, &pubj, &key);
    secp256k1_ge_set_gej(&pub, &pubj);

    /* obtain a working nonce */
    do {
        random_scalar_order_test(&nonce);
    } while(!secp256k1_ecdsa_sig_sign(&both->ecmult_gen_ctx, &sigr, &sigs, &key, &msg, &nonce, NULL));

    /* try signing */
    CHECK(secp256k1_ecdsa_sig_sign(&sign->ecmult_gen_ctx, &sigr, &sigs, &key, &msg, &nonce, NULL));
    CHECK(secp256k1_ecdsa_sig_sign(&both->ecmult_gen_ctx, &sigr, &sigs, &key, &msg, &nonce, NULL));

    /* try verifying */
    CHECK(secp256k1_ecdsa_sig_verify(&vrfy->ecmult_ctx, &sigr, &sigs, &pub, &msg));
    CHECK(secp256k1_ecdsa_sig_verify(&both->ecmult_ctx, &sigr, &sigs, &pub, &msg));

    /* cleanup */
    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(vrfy);
    secp256k1_context_destroy(both);
}

/***** HASH TESTS *****/

void run_sha256_tests(void) {
    static const char *inputs[8] = {
        "", "abc", "message digest", "secure hash algorithm", "SHA256 is considered to be safe",
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "For this sample, this 63-byte string will be used as input data",
        "This is exactly 64 bytes long, not counting the terminating byte"
    };
    static const unsigned char outputs[8][32] = {
        {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55},
        {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad},
        {0xf7, 0x84, 0x6f, 0x55, 0xcf, 0x23, 0xe1, 0x4e, 0xeb, 0xea, 0xb5, 0xb4, 0xe1, 0x55, 0x0c, 0xad, 0x5b, 0x50, 0x9e, 0x33, 0x48, 0xfb, 0xc4, 0xef, 0xa3, 0xa1, 0x41, 0x3d, 0x39, 0x3c, 0xb6, 0x50},
        {0xf3, 0x0c, 0xeb, 0x2b, 0xb2, 0x82, 0x9e, 0x79, 0xe4, 0xca, 0x97, 0x53, 0xd3, 0x5a, 0x8e, 0xcc, 0x00, 0x26, 0x2d, 0x16, 0x4c, 0xc0, 0x77, 0x08, 0x02, 0x95, 0x38, 0x1c, 0xbd, 0x64, 0x3f, 0x0d},
        {0x68, 0x19, 0xd9, 0x15, 0xc7, 0x3f, 0x4d, 0x1e, 0x77, 0xe4, 0xe1, 0xb5, 0x2d, 0x1f, 0xa0, 0xf9, 0xcf, 0x9b, 0xea, 0xea, 0xd3, 0x93, 0x9f, 0x15, 0x87, 0x4b, 0xd9, 0x88, 0xe2, 0xa2, 0x36, 0x30},
        {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1},
        {0xf0, 0x8a, 0x78, 0xcb, 0xba, 0xee, 0x08, 0x2b, 0x05, 0x2a, 0xe0, 0x70, 0x8f, 0x32, 0xfa, 0x1e, 0x50, 0xc5, 0xc4, 0x21, 0xaa, 0x77, 0x2b, 0xa5, 0xdb, 0xb4, 0x06, 0xa2, 0xea, 0x6b, 0xe3, 0x42},
        {0xab, 0x64, 0xef, 0xf7, 0xe8, 0x8e, 0x2e, 0x46, 0x16, 0x5e, 0x29, 0xf2, 0xbc, 0xe4, 0x18, 0x26, 0xbd, 0x4c, 0x7b, 0x35, 0x52, 0xf6, 0xb3, 0x82, 0xa9, 0xe7, 0xd3, 0xaf, 0x47, 0xc2, 0x45, 0xf8}
    };
    int i;
    for (i = 0; i < 8; i++) {
        unsigned char out[32];
        secp256k1_sha256_t hasher;
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hasher, (const unsigned char*)(inputs[i]), strlen(inputs[i]));
        secp256k1_sha256_finalize(&hasher, out);
        CHECK(memcmp(out, outputs[i], 32) == 0);
        if (strlen(inputs[i]) > 0) {
            int split = secp256k1_rand32() % strlen(inputs[i]);
            secp256k1_sha256_initialize(&hasher);
            secp256k1_sha256_write(&hasher, (const unsigned char*)(inputs[i]), split);
            secp256k1_sha256_write(&hasher, (const unsigned char*)(inputs[i] + split), strlen(inputs[i]) - split);
            secp256k1_sha256_finalize(&hasher, out);
            CHECK(memcmp(out, outputs[i], 32) == 0);
        }
    }
}

void run_hmac_sha256_tests(void) {
    static const char *keys[6] = {
        "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
        "\x4a\x65\x66\x65",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa",
        "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
    };
    static const char *inputs[6] = {
        "\x48\x69\x20\x54\x68\x65\x72\x65",
        "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f",
        "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
        "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
        "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79\x20\x46\x69\x72\x73\x74",
        "\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20\x75\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20\x68\x61\x73\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20\x62\x79\x20\x74\x68\x65\x20\x48\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68\x6d\x2e"
    };
    static const unsigned char outputs[6][32] = {
        {0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7},
        {0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43},
        {0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe},
        {0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08, 0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29, 0x66, 0x5b},
        {0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f, 0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f, 0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14, 0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54},
        {0x9b, 0x09, 0xff, 0xa7, 0x1b, 0x94, 0x2f, 0xcb, 0x27, 0x63, 0x5f, 0xbc, 0xd5, 0xb0, 0xe9, 0x44, 0xbf, 0xdc, 0x63, 0x64, 0x4f, 0x07, 0x13, 0x93, 0x8a, 0x7f, 0x51, 0x53, 0x5c, 0x3a, 0x35, 0xe2}
    };
    int i;
    for (i = 0; i < 6; i++) {
        secp256k1_hmac_sha256_t hasher;
        unsigned char out[32];
        secp256k1_hmac_sha256_initialize(&hasher, (const unsigned char*)(keys[i]), strlen(keys[i]));
        secp256k1_hmac_sha256_write(&hasher, (const unsigned char*)(inputs[i]), strlen(inputs[i]));
        secp256k1_hmac_sha256_finalize(&hasher, out);
        CHECK(memcmp(out, outputs[i], 32) == 0);
        if (strlen(inputs[i]) > 0) {
            int split = secp256k1_rand32() % strlen(inputs[i]);
            secp256k1_hmac_sha256_initialize(&hasher, (const unsigned char*)(keys[i]), strlen(keys[i]));
            secp256k1_hmac_sha256_write(&hasher, (const unsigned char*)(inputs[i]), split);
            secp256k1_hmac_sha256_write(&hasher, (const unsigned char*)(inputs[i] + split), strlen(inputs[i]) - split);
            secp256k1_hmac_sha256_finalize(&hasher, out);
            CHECK(memcmp(out, outputs[i], 32) == 0);
        }
    }
}

void run_rfc6979_hmac_sha256_tests(void) {
    static const unsigned char key1[65] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x4b, 0xf5, 0x12, 0x2f, 0x34, 0x45, 0x54, 0xc5, 0x3b, 0xde, 0x2e, 0xbb, 0x8c, 0xd2, 0xb7, 0xe3, 0xd1, 0x60, 0x0a, 0xd6, 0x31, 0xc3, 0x85, 0xa5, 0xd7, 0xcc, 0xe2, 0x3c, 0x77, 0x85, 0x45, 0x9a, 0};
    static const unsigned char out1[3][32] = {
        {0x4f, 0xe2, 0x95, 0x25, 0xb2, 0x08, 0x68, 0x09, 0x15, 0x9a, 0xcd, 0xf0, 0x50, 0x6e, 0xfb, 0x86, 0xb0, 0xec, 0x93, 0x2c, 0x7b, 0xa4, 0x42, 0x56, 0xab, 0x32, 0x1e, 0x42, 0x1e, 0x67, 0xe9, 0xfb},
        {0x2b, 0xf0, 0xff, 0xf1, 0xd3, 0xc3, 0x78, 0xa2, 0x2d, 0xc5, 0xde, 0x1d, 0x85, 0x65, 0x22, 0x32, 0x5c, 0x65, 0xb5, 0x04, 0x49, 0x1a, 0x0c, 0xbd, 0x01, 0xcb, 0x8f, 0x3a, 0xa6, 0x7f, 0xfd, 0x4a},
        {0xf5, 0x28, 0xb4, 0x10, 0xcb, 0x54, 0x1f, 0x77, 0x00, 0x0d, 0x7a, 0xfb, 0x6c, 0x5b, 0x53, 0xc5, 0xc4, 0x71, 0xea, 0xb4, 0x3e, 0x46, 0x6d, 0x9a, 0xc5, 0x19, 0x0c, 0x39, 0xc8, 0x2f, 0xd8, 0x2e}
    };

    static const unsigned char key2[64] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    static const unsigned char out2[3][32] = {
        {0x9c, 0x23, 0x6c, 0x16, 0x5b, 0x82, 0xae, 0x0c, 0xd5, 0x90, 0x65, 0x9e, 0x10, 0x0b, 0x6b, 0xab, 0x30, 0x36, 0xe7, 0xba, 0x8b, 0x06, 0x74, 0x9b, 0xaf, 0x69, 0x81, 0xe1, 0x6f, 0x1a, 0x2b, 0x95},
        {0xdf, 0x47, 0x10, 0x61, 0x62, 0x5b, 0xc0, 0xea, 0x14, 0xb6, 0x82, 0xfe, 0xee, 0x2c, 0x9c, 0x02, 0xf2, 0x35, 0xda, 0x04, 0x20, 0x4c, 0x1d, 0x62, 0xa1, 0x53, 0x6c, 0x6e, 0x17, 0xae, 0xd7, 0xa9},
        {0x75, 0x97, 0x88, 0x7c, 0xbd, 0x76, 0x32, 0x1f, 0x32, 0xe3, 0x04, 0x40, 0x67, 0x9a, 0x22, 0xcf, 0x7f, 0x8d, 0x9d, 0x2e, 0xac, 0x39, 0x0e, 0x58, 0x1f, 0xea, 0x09, 0x1c, 0xe2, 0x02, 0xba, 0x94}
    };

    secp256k1_rfc6979_hmac_sha256_t rng;
    unsigned char out[32];
    int i;

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, key1, 64);
    for (i = 0; i < 3; i++) {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, out, 32);
        CHECK(memcmp(out, out1[i], 32) == 0);
    }
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, key1, 65);
    for (i = 0; i < 3; i++) {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, out, 32);
        CHECK(memcmp(out, out1[i], 32) != 0);
    }
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);

    secp256k1_rfc6979_hmac_sha256_initialize(&rng, key2, 64);
    for (i = 0; i < 3; i++) {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, out, 32);
        CHECK(memcmp(out, out2[i], 32) == 0);
    }
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
}

/***** NUM TESTS *****/

#ifndef USE_NUM_NONE
void random_num_negate(secp256k1_num *num) {
    if (secp256k1_rand32() & 1) {
        secp256k1_num_negate(num);
    }
}

void random_num_order_test(secp256k1_num *num) {
    secp256k1_scalar sc;
    random_scalar_order_test(&sc);
    secp256k1_scalar_get_num(num, &sc);
}

void random_num_order(secp256k1_num *num) {
    secp256k1_scalar sc;
    random_scalar_order(&sc);
    secp256k1_scalar_get_num(num, &sc);
}

void test_num_negate(void) {
    secp256k1_num n1;
    secp256k1_num n2;
    random_num_order_test(&n1); /* n1 = R */
    random_num_negate(&n1);
    secp256k1_num_copy(&n2, &n1); /* n2 = R */
    secp256k1_num_sub(&n1, &n2, &n1); /* n1 = n2-n1 = 0 */
    CHECK(secp256k1_num_is_zero(&n1));
    secp256k1_num_copy(&n1, &n2); /* n1 = R */
    secp256k1_num_negate(&n1); /* n1 = -R */
    CHECK(!secp256k1_num_is_zero(&n1));
    secp256k1_num_add(&n1, &n2, &n1); /* n1 = n2+n1 = 0 */
    CHECK(secp256k1_num_is_zero(&n1));
    secp256k1_num_copy(&n1, &n2); /* n1 = R */
    secp256k1_num_negate(&n1); /* n1 = -R */
    CHECK(secp256k1_num_is_neg(&n1) != secp256k1_num_is_neg(&n2));
    secp256k1_num_negate(&n1); /* n1 = R */
    CHECK(secp256k1_num_eq(&n1, &n2));
}

void test_num_add_sub(void) {
    secp256k1_num n1;
    secp256k1_num n2;
    secp256k1_num n1p2, n2p1, n1m2, n2m1;
    int r = secp256k1_rand32();
    random_num_order_test(&n1); /* n1 = R1 */
    if (r & 1) {
        random_num_negate(&n1);
    }
    random_num_order_test(&n2); /* n2 = R2 */
    if (r & 2) {
        random_num_negate(&n2);
    }
    secp256k1_num_add(&n1p2, &n1, &n2); /* n1p2 = R1 + R2 */
    secp256k1_num_add(&n2p1, &n2, &n1); /* n2p1 = R2 + R1 */
    secp256k1_num_sub(&n1m2, &n1, &n2); /* n1m2 = R1 - R2 */
    secp256k1_num_sub(&n2m1, &n2, &n1); /* n2m1 = R2 - R1 */
    CHECK(secp256k1_num_eq(&n1p2, &n2p1));
    CHECK(!secp256k1_num_eq(&n1p2, &n1m2));
    secp256k1_num_negate(&n2m1); /* n2m1 = -R2 + R1 */
    CHECK(secp256k1_num_eq(&n2m1, &n1m2));
    CHECK(!secp256k1_num_eq(&n2m1, &n1));
    secp256k1_num_add(&n2m1, &n2m1, &n2); /* n2m1 = -R2 + R1 + R2 = R1 */
    CHECK(secp256k1_num_eq(&n2m1, &n1));
    CHECK(!secp256k1_num_eq(&n2p1, &n1));
    secp256k1_num_sub(&n2p1, &n2p1, &n2); /* n2p1 = R2 + R1 - R2 = R1 */
    CHECK(secp256k1_num_eq(&n2p1, &n1));
}

void run_num_smalltests(void) {
    int i;
    for (i = 0; i < 100*count; i++) {
        test_num_negate();
        test_num_add_sub();
    }
}
#endif

/***** SCALAR TESTS *****/

void scalar_test(void) {
    secp256k1_scalar s;
    secp256k1_scalar s1;
    secp256k1_scalar s2;
#ifndef USE_NUM_NONE
    secp256k1_num snum, s1num, s2num;
    secp256k1_num order, half_order;
#endif
    unsigned char c[32];

    /* Set 's' to a random scalar, with value 'snum'. */
    random_scalar_order_test(&s);

    /* Set 's1' to a random scalar, with value 's1num'. */
    random_scalar_order_test(&s1);

    /* Set 's2' to a random scalar, with value 'snum2', and byte array representation 'c'. */
    random_scalar_order_test(&s2);
    secp256k1_scalar_get_b32(c, &s2);

#ifndef USE_NUM_NONE
    secp256k1_scalar_get_num(&snum, &s);
    secp256k1_scalar_get_num(&s1num, &s1);
    secp256k1_scalar_get_num(&s2num, &s2);

    secp256k1_scalar_order_get_num(&order);
    half_order = order;
    secp256k1_num_shift(&half_order, 1);
#endif

    {
        int i;
        /* Test that fetching groups of 4 bits from a scalar and recursing n(i)=16*n(i-1)+p(i) reconstructs it. */
        secp256k1_scalar n;
        secp256k1_scalar_set_int(&n, 0);
        for (i = 0; i < 256; i += 4) {
            secp256k1_scalar t;
            int j;
            secp256k1_scalar_set_int(&t, secp256k1_scalar_get_bits(&s, 256 - 4 - i, 4));
            for (j = 0; j < 4; j++) {
                secp256k1_scalar_add(&n, &n, &n);
            }
            secp256k1_scalar_add(&n, &n, &t);
        }
        CHECK(secp256k1_scalar_eq(&n, &s));
    }

    {
        /* Test that fetching groups of randomly-sized bits from a scalar and recursing n(i)=b*n(i-1)+p(i) reconstructs it. */
        secp256k1_scalar n;
        int i = 0;
        secp256k1_scalar_set_int(&n, 0);
        while (i < 256) {
            secp256k1_scalar t;
            int j;
            int now = (secp256k1_rand32() % 15) + 1;
            if (now + i > 256) {
                now = 256 - i;
            }
            secp256k1_scalar_set_int(&t, secp256k1_scalar_get_bits_var(&s, 256 - now - i, now));
            for (j = 0; j < now; j++) {
                secp256k1_scalar_add(&n, &n, &n);
            }
            secp256k1_scalar_add(&n, &n, &t);
            i += now;
        }
        CHECK(secp256k1_scalar_eq(&n, &s));
    }

#ifndef USE_NUM_NONE
    {
        /* Test that adding the scalars together is equal to adding their numbers together modulo the order. */
        secp256k1_num rnum;
        secp256k1_num r2num;
        secp256k1_scalar r;
        secp256k1_num_add(&rnum, &snum, &s2num);
        secp256k1_num_mod(&rnum, &order);
        secp256k1_scalar_add(&r, &s, &s2);
        secp256k1_scalar_get_num(&r2num, &r);
        CHECK(secp256k1_num_eq(&rnum, &r2num));
    }

    {
        /* Test that multipying the scalars is equal to multiplying their numbers modulo the order. */
        secp256k1_scalar r;
        secp256k1_num r2num;
        secp256k1_num rnum;
        secp256k1_num_mul(&rnum, &snum, &s2num);
        secp256k1_num_mod(&rnum, &order);
        secp256k1_scalar_mul(&r, &s, &s2);
        secp256k1_scalar_get_num(&r2num, &r);
        CHECK(secp256k1_num_eq(&rnum, &r2num));
        /* The result can only be zero if at least one of the factors was zero. */
        CHECK(secp256k1_scalar_is_zero(&r) == (secp256k1_scalar_is_zero(&s) || secp256k1_scalar_is_zero(&s2)));
        /* The results can only be equal to one of the factors if that factor was zero, or the other factor was one. */
        CHECK(secp256k1_num_eq(&rnum, &snum) == (secp256k1_scalar_is_zero(&s) || secp256k1_scalar_is_one(&s2)));
        CHECK(secp256k1_num_eq(&rnum, &s2num) == (secp256k1_scalar_is_zero(&s2) || secp256k1_scalar_is_one(&s)));
    }

    {
        secp256k1_scalar neg;
        secp256k1_num negnum;
        secp256k1_num negnum2;
        /* Check that comparison with zero matches comparison with zero on the number. */
        CHECK(secp256k1_num_is_zero(&snum) == secp256k1_scalar_is_zero(&s));
        /* Check that comparison with the half order is equal to testing for high scalar. */
        CHECK(secp256k1_scalar_is_high(&s) == (secp256k1_num_cmp(&snum, &half_order) > 0));
        secp256k1_scalar_negate(&neg, &s);
        secp256k1_num_sub(&negnum, &order, &snum);
        secp256k1_num_mod(&negnum, &order);
        /* Check that comparison with the half order is equal to testing for high scalar after negation. */
        CHECK(secp256k1_scalar_is_high(&neg) == (secp256k1_num_cmp(&negnum, &half_order) > 0));
        /* Negating should change the high property, unless the value was already zero. */
        CHECK((secp256k1_scalar_is_high(&s) == secp256k1_scalar_is_high(&neg)) == secp256k1_scalar_is_zero(&s));
        secp256k1_scalar_get_num(&negnum2, &neg);
        /* Negating a scalar should be equal to (order - n) mod order on the number. */
        CHECK(secp256k1_num_eq(&negnum, &negnum2));
        secp256k1_scalar_add(&neg, &neg, &s);
        /* Adding a number to its negation should result in zero. */
        CHECK(secp256k1_scalar_is_zero(&neg));
        secp256k1_scalar_negate(&neg, &neg);
        /* Negating zero should still result in zero. */
        CHECK(secp256k1_scalar_is_zero(&neg));
    }

    {
        /* Test secp256k1_scalar_mul_shift_var. */
        secp256k1_scalar r;
        secp256k1_num one;
        secp256k1_num rnum;
        secp256k1_num rnum2;
        unsigned char cone[1] = {0x01};
        unsigned int shift = 256 + (secp256k1_rand32() % 257);
        secp256k1_scalar_mul_shift_var(&r, &s1, &s2, shift);
        secp256k1_num_mul(&rnum, &s1num, &s2num);
        secp256k1_num_shift(&rnum, shift - 1);
        secp256k1_num_set_bin(&one, cone, 1);
        secp256k1_num_add(&rnum, &rnum, &one);
        secp256k1_num_shift(&rnum, 1);
        secp256k1_scalar_get_num(&rnum2, &r);
        CHECK(secp256k1_num_eq(&rnum, &rnum2));
    }

    {
        /* test secp256k1_scalar_shr_int */
        secp256k1_scalar r;
        int i;
        random_scalar_order_test(&r);
        for (i = 0; i < 100; ++i) {
            int low;
            int shift = 1 + (secp256k1_rand32() % 15);
            int expected = r.d[0] % (1 << shift);
            low = secp256k1_scalar_shr_int(&r, shift);
            CHECK(expected == low);
        }
    }
#endif

    {
        /* Test that scalar inverses are equal to the inverse of their number modulo the order. */
        if (!secp256k1_scalar_is_zero(&s)) {
            secp256k1_scalar inv;
#ifndef USE_NUM_NONE
            secp256k1_num invnum;
            secp256k1_num invnum2;
#endif
            secp256k1_scalar_inverse(&inv, &s);
#ifndef USE_NUM_NONE
            secp256k1_num_mod_inverse(&invnum, &snum, &order);
            secp256k1_scalar_get_num(&invnum2, &inv);
            CHECK(secp256k1_num_eq(&invnum, &invnum2));
#endif
            secp256k1_scalar_mul(&inv, &inv, &s);
            /* Multiplying a scalar with its inverse must result in one. */
            CHECK(secp256k1_scalar_is_one(&inv));
            secp256k1_scalar_inverse(&inv, &inv);
            /* Inverting one must result in one. */
            CHECK(secp256k1_scalar_is_one(&inv));
        }
    }

    {
        /* Test commutativity of add. */
        secp256k1_scalar r1, r2;
        secp256k1_scalar_add(&r1, &s1, &s2);
        secp256k1_scalar_add(&r2, &s2, &s1);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }

    {
        secp256k1_scalar r1, r2;
        secp256k1_scalar b;
        int i;
        /* Test add_bit. */
        int bit = secp256k1_rand32() % 256;
        secp256k1_scalar_set_int(&b, 1);
        CHECK(secp256k1_scalar_is_one(&b));
        for (i = 0; i < bit; i++) {
            secp256k1_scalar_add(&b, &b, &b);
        }
        r1 = s1;
        r2 = s1;
        if (!secp256k1_scalar_add(&r1, &r1, &b)) {
            /* No overflow happened. */
            secp256k1_scalar_cadd_bit(&r2, bit, 1);
            CHECK(secp256k1_scalar_eq(&r1, &r2));
            /* cadd is a noop when flag is zero */
            secp256k1_scalar_cadd_bit(&r2, bit, 0);
            CHECK(secp256k1_scalar_eq(&r1, &r2));
        }
    }

    {
        /* Test commutativity of mul. */
        secp256k1_scalar r1, r2;
        secp256k1_scalar_mulX(&r1, &s1, &s2);
        secp256k1_scalar_mulX(&r2, &s2, &s1);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test associativity of add. */
        secp256k1_scalar r1, r2;
        secp256k1_scalar_add(&r1, &s1, &s2);
        secp256k1_scalar_add(&r1, &r1, &s);
        secp256k1_scalar_add(&r2, &s2, &s);
        secp256k1_scalar_add(&r2, &s1, &r2);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test associativity of mul. */
        secp256k1_scalar r1, r2;
        secp256k1_scalar_mulX(&r1, &s1, &s2);
        secp256k1_scalar_mulX(&r1, &r1, &s);
        secp256k1_scalar_mulX(&r2, &s2, &s);
        secp256k1_scalar_mulX(&r2, &s1, &r2);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test distributitivity of mul over add. */
        secp256k1_scalar r1, r2, t;
        secp256k1_scalar_add(&r1, &s1, &s2);
        secp256k1_scalar_mul(&r1, &r1, &s);
        secp256k1_scalar_mul(&r2, &s1, &s);
        secp256k1_scalar_mul(&t, &s2, &s);
        secp256k1_scalar_add(&r2, &r2, &t);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test square. */
        secp256k1_scalar r1, r2;
        secp256k1_scalar_sqr(&r1, &s1);
        secp256k1_scalar_mul(&r2, &s1, &s1);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }

    {
        /* Test multiplicative identity. */
        secp256k1_scalar r1, v1;
        secp256k1_scalar_set_int(&v1,1);
        secp256k1_scalar_mul(&r1, &s1, &v1);
        CHECK(secp256k1_scalar_eq(&r1, &s1));
    }

    {
        /* Test additive identity. */
        secp256k1_scalar r1, v0;
        secp256k1_scalar_set_int(&v0,0);
        secp256k1_scalar_add(&r1, &s1, &v0);
        CHECK(secp256k1_scalar_eq(&r1, &s1));
    }

    {
        /* Test zero product property. */
        secp256k1_scalar r1, v0;
        secp256k1_scalar_set_int(&v0,0);
        secp256k1_scalar_mul(&r1, &s1, &v0);
        CHECK(secp256k1_scalar_eq(&r1, &v0));
    }

}

void run_scalar_tests(void) {
    int i;
    for (i = 0; i < 128 * count; i++) {
        scalar_test();
    }

    {
        /* (-1)+1 should be zero. */
        secp256k1_scalar s, o;
        secp256k1_scalar_set_int(&s, 1);
        CHECK(secp256k1_scalar_is_one(&s));
        secp256k1_scalar_negate(&o, &s);
        secp256k1_scalar_add(&o, &o, &s);
        CHECK(secp256k1_scalar_is_zero(&o));
        secp256k1_scalar_negate(&o, &o);
        CHECK(secp256k1_scalar_is_zero(&o));
    }

#ifndef USE_NUM_NONE
    {
        /* A scalar with value of the curve order should be 0. */
        secp256k1_num order;
        secp256k1_scalar zero;
        unsigned char bin[32];
        int overflow = 0;
        secp256k1_scalar_order_get_num(&order);
        secp256k1_num_get_bin(bin, 32, &order);
        secp256k1_scalar_set_b32(&zero, bin, &overflow);
        CHECK(overflow == 1);
        CHECK(secp256k1_scalar_is_zero(&zero));
    }
#endif
}

/***** FIELD TESTS *****/

void random_fe(secp256k1_fe *x) {
    unsigned char bin[32];
    do {
        secp256k1_rand256(bin);
        if (secp256k1_fe_set_b32(x, bin)) {
            return;
        }
    } while(1);
}

void random_fe_non_zero(secp256k1_fe *nz) {
    int tries = 10;
    while (--tries >= 0) {
        random_fe(nz);
        secp256k1_fe_normalize(nz);
        if (!secp256k1_fe_is_zero(nz)) {
            break;
        }
    }
    /* Infinitesimal probability of spurious failure here */
    CHECK(tries >= 0);
}

void random_fe_non_square(secp256k1_fe *ns) {
    secp256k1_fe r;
    random_fe_non_zero(ns);
    if (secp256k1_fe_sqrt_var(&r, ns)) {
        secp256k1_fe_negate(ns, ns, 1);
    }
}

int check_fe_equal(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe an = *a;
    secp256k1_fe bn = *b;
    secp256k1_fe_normalize_weak(&an);
    secp256k1_fe_normalize_var(&bn);
    return secp256k1_fe_equal_var(&an, &bn);
}

int check_fe_inverse(const secp256k1_fe *a, const secp256k1_fe *ai) {
    secp256k1_fe x;
    secp256k1_fe one = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    secp256k1_fe_mul(&x, a, ai);
    return check_fe_equal(&x, &one);
}

void run_field_convert(void) {
    static const unsigned char b32[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x40
    };
    static const secp256k1_fe_storage fes = SECP256K1_FE_STORAGE_CONST(
        0x00010203UL, 0x04050607UL, 0x11121314UL, 0x15161718UL,
        0x22232425UL, 0x26272829UL, 0x33343536UL, 0x37383940UL
    );
    static const secp256k1_fe fe = SECP256K1_FE_CONST(
        0x00010203UL, 0x04050607UL, 0x11121314UL, 0x15161718UL,
        0x22232425UL, 0x26272829UL, 0x33343536UL, 0x37383940UL
    );
    secp256k1_fe fe2;
    unsigned char b322[32];
    secp256k1_fe_storage fes2;
    /* Check conversions to fe. */
    CHECK(secp256k1_fe_set_b32(&fe2, b32));
    CHECK(secp256k1_fe_equal_var(&fe, &fe2));
    secp256k1_fe_from_storage(&fe2, &fes);
    CHECK(secp256k1_fe_equal_var(&fe, &fe2));
    /* Check conversion from fe. */
    secp256k1_fe_get_b32(b322, &fe);
    CHECK(memcmp(b322, b32, 32) == 0);
    secp256k1_fe_to_storage(&fes2, &fe);
    CHECK(memcmp(&fes2, &fes, sizeof(fes)) == 0);
}

int fe_memcmp(const secp256k1_fe *a, const secp256k1_fe *b) {
    secp256k1_fe t = *b;
#ifdef VERIFY
    t.magnitude = a->magnitude;
    t.normalized = a->normalized;
#endif
    return memcmp(a, &t, sizeof(secp256k1_fe));
}

void run_field_misc(void) {
    secp256k1_fe x;
    secp256k1_fe y;
    secp256k1_fe z;
    secp256k1_fe q;
    secp256k1_fe fe5 = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 5);
    int i, j;
    for (i = 0; i < 5*count; i++) {
        secp256k1_fe_storage xs, ys, zs;
        random_fe(&x);
        random_fe_non_zero(&y);
        /* Test the fe equality and comparison operations. */
        CHECK(secp256k1_fe_cmp_var(&x, &x) == 0);
        CHECK(secp256k1_fe_equal_var(&x, &x));
        z = x;
        secp256k1_fe_add(&z,&y);
        /* Test fe conditional move; z is not normalized here. */
        q = x;
        secp256k1_fe_cmov(&x, &z, 0);
        VERIFY_CHECK(!x.normalized && x.magnitude == z.magnitude);
        secp256k1_fe_cmov(&x, &x, 1);
        CHECK(fe_memcmp(&x, &z) != 0);
        CHECK(fe_memcmp(&x, &q) == 0);
        secp256k1_fe_cmov(&q, &z, 1);
        VERIFY_CHECK(!q.normalized && q.magnitude == z.magnitude);
        CHECK(fe_memcmp(&q, &z) == 0);
        secp256k1_fe_normalize_var(&x);
        secp256k1_fe_normalize_var(&z);
        CHECK(!secp256k1_fe_equal_var(&x, &z));
        secp256k1_fe_normalize_var(&q);
        secp256k1_fe_cmov(&q, &z, (i&1));
        VERIFY_CHECK(q.normalized && q.magnitude == 1);
        for (j = 0; j < 6; j++) {
            secp256k1_fe_negate(&z, &z, j+1);
            secp256k1_fe_normalize_var(&q);
            secp256k1_fe_cmov(&q, &z, (j&1));
            VERIFY_CHECK(!q.normalized && q.magnitude == (j+2));
        }
        secp256k1_fe_normalize_var(&z);
        /* Test storage conversion and conditional moves. */
        secp256k1_fe_to_storage(&xs, &x);
        secp256k1_fe_to_storage(&ys, &y);
        secp256k1_fe_to_storage(&zs, &z);
        secp256k1_fe_storage_cmov(&zs, &xs, 0);
        secp256k1_fe_storage_cmov(&zs, &zs, 1);
        CHECK(memcmp(&xs, &zs, sizeof(xs)) != 0);
        secp256k1_fe_storage_cmov(&ys, &xs, 1);
        CHECK(memcmp(&xs, &ys, sizeof(xs)) == 0);
        secp256k1_fe_from_storage(&x, &xs);
        secp256k1_fe_from_storage(&y, &ys);
        secp256k1_fe_from_storage(&z, &zs);
        /* Test that mul_int, mul, and add agree. */
        secp256k1_fe_add(&y, &x);
        secp256k1_fe_add(&y, &x);
        z = x;
        secp256k1_fe_mul_int(&z, 3);
        CHECK(check_fe_equal(&y, &z));
        secp256k1_fe_add(&y, &x);
        secp256k1_fe_add(&z, &x);
        CHECK(check_fe_equal(&z, &y));
        z = x;
        secp256k1_fe_mul_int(&z, 5);
        secp256k1_fe_mul(&q, &x, &fe5);
        CHECK(check_fe_equal(&z, &q));
        secp256k1_fe_negate(&x, &x, 1);
        secp256k1_fe_add(&z, &x);
        secp256k1_fe_add(&q, &x);
        CHECK(check_fe_equal(&y, &z));
        CHECK(check_fe_equal(&q, &y));
    }
}

void run_field_inv(void) {
    secp256k1_fe x, xi, xii;
    int i;
    for (i = 0; i < 10*count; i++) {
        random_fe_non_zero(&x);
        secp256k1_fe_inv(&xi, &x);
        CHECK(check_fe_inverse(&x, &xi));
        secp256k1_fe_inv(&xii, &xi);
        CHECK(check_fe_equal(&x, &xii));
    }
}

void run_field_inv_var(void) {
    secp256k1_fe x, xi, xii;
    int i;
    for (i = 0; i < 10*count; i++) {
        random_fe_non_zero(&x);
        secp256k1_fe_inv_var(&xi, &x);
        CHECK(check_fe_inverse(&x, &xi));
        secp256k1_fe_inv_var(&xii, &xi);
        CHECK(check_fe_equal(&x, &xii));
    }
}

void run_field_inv_all_var(void) {
    secp256k1_fe x[16], xi[16], xii[16];
    int i;
    /* Check it's safe to call for 0 elements */
    secp256k1_fe_inv_all_var(0, xi, x);
    for (i = 0; i < count; i++) {
        size_t j;
        size_t len = (secp256k1_rand32() & 15) + 1;
        for (j = 0; j < len; j++) {
            random_fe_non_zero(&x[j]);
        }
        secp256k1_fe_inv_all_var(len, xi, x);
        for (j = 0; j < len; j++) {
            CHECK(check_fe_inverse(&x[j], &xi[j]));
        }
        secp256k1_fe_inv_all_var(len, xii, xi);
        for (j = 0; j < len; j++) {
            CHECK(check_fe_equal(&x[j], &xii[j]));
        }
    }
}

void run_sqr(void) {
    secp256k1_fe x, s;

    {
        int i;
        secp256k1_fe_set_int(&x, 1);
        secp256k1_fe_negate(&x, &x, 1);

        for (i = 1; i <= 512; ++i) {
            secp256k1_fe_mul_int(&x, 2);
            secp256k1_fe_normalize(&x);
            secp256k1_fe_sqr(&s, &x);
        }
    }
}

void test_sqrt(const secp256k1_fe *a, const secp256k1_fe *k) {
    secp256k1_fe r1, r2;
    int v = secp256k1_fe_sqrt_var(&r1, a);
    CHECK((v == 0) == (k == NULL));

    if (k != NULL) {
        /* Check that the returned root is +/- the given known answer */
        secp256k1_fe_negate(&r2, &r1, 1);
        secp256k1_fe_add(&r1, k); secp256k1_fe_add(&r2, k);
        secp256k1_fe_normalize(&r1); secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_is_zero(&r1) || secp256k1_fe_is_zero(&r2));
    }
}

void run_sqrt(void) {
    secp256k1_fe ns, x, s, t;
    int i;

    /* Check sqrt(0) is 0 */
    secp256k1_fe_set_int(&x, 0);
    secp256k1_fe_sqr(&s, &x);
    test_sqrt(&s, &x);

    /* Check sqrt of small squares (and their negatives) */
    for (i = 1; i <= 100; i++) {
        secp256k1_fe_set_int(&x, i);
        secp256k1_fe_sqr(&s, &x);
        test_sqrt(&s, &x);
        secp256k1_fe_negate(&t, &s, 1);
        test_sqrt(&t, NULL);
    }

    /* Consistency checks for large random values */
    for (i = 0; i < 10; i++) {
        int j;
        random_fe_non_square(&ns);
        for (j = 0; j < count; j++) {
            random_fe(&x);
            secp256k1_fe_sqr(&s, &x);
            test_sqrt(&s, &x);
            secp256k1_fe_negate(&t, &s, 1);
            test_sqrt(&t, NULL);
            secp256k1_fe_mul(&t, &s, &ns);
            test_sqrt(&t, NULL);
        }
    }
}

/***** GROUP TESTS *****/

void ge_equals_ge(const secp256k1_ge *a, const secp256k1_ge *b) {
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    CHECK(secp256k1_fe_equal_var(&a->x, &b->x));
    CHECK(secp256k1_fe_equal_var(&a->y, &b->y));
}

/* This compares jacobian points including their Z, not just their geometric meaning. */
int gej_xyz_equals_gej(const secp256k1_gej *a, const secp256k1_gej *b) {
    secp256k1_gej a2;
    secp256k1_gej b2;
    int ret = 1;
    ret &= a->infinity == b->infinity;
    if (ret && !a->infinity) {
        a2 = *a;
        b2 = *b;
        secp256k1_fe_normalize(&a2.x);
        secp256k1_fe_normalize(&a2.y);
        secp256k1_fe_normalize(&a2.z);
        secp256k1_fe_normalize(&b2.x);
        secp256k1_fe_normalize(&b2.y);
        secp256k1_fe_normalize(&b2.z);
        ret &= secp256k1_fe_cmp_var(&a2.x, &b2.x) == 0;
        ret &= secp256k1_fe_cmp_var(&a2.y, &b2.y) == 0;
        ret &= secp256k1_fe_cmp_var(&a2.z, &b2.z) == 0;
    }
    return ret;
}

void ge_equals_gej(const secp256k1_ge *a, const secp256k1_gej *b) {
    secp256k1_fe z2s;
    secp256k1_fe u1, u2, s1, s2;
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    /* Check a.x * b.z^2 == b.x && a.y * b.z^3 == b.y, to avoid inverses. */
    secp256k1_fe_sqr(&z2s, &b->z);
    secp256k1_fe_mul(&u1, &a->x, &z2s);
    u2 = b->x; secp256k1_fe_normalize_weak(&u2);
    secp256k1_fe_mul(&s1, &a->y, &z2s); secp256k1_fe_mul(&s1, &s1, &b->z);
    s2 = b->y; secp256k1_fe_normalize_weak(&s2);
    CHECK(secp256k1_fe_equal_var(&u1, &u2));
    CHECK(secp256k1_fe_equal_var(&s1, &s2));
}

void test_ge(void) {
    int i, i1;
#ifdef USE_ENDOMORPHISM
    int runs = 6;
#else
    int runs = 4;
#endif
    /* Points: (infinity, p1, p1, -p1, -p1, p2, p2, -p2, -p2, p3, p3, -p3, -p3, p4, p4, -p4, -p4).
     * The second in each pair of identical points uses a random Z coordinate in the Jacobian form.
     * All magnitudes are randomized.
     * All 17*17 combinations of points are added to eachother, using all applicable methods.
     *
     * When the endomorphism code is compiled in, p5 = lambda*p1 and p6 = lambda^2*p1 are added as well.
     */
    secp256k1_ge *ge = (secp256k1_ge *)malloc(sizeof(secp256k1_ge) * (1 + 4 * runs));
    secp256k1_gej *gej = (secp256k1_gej *)malloc(sizeof(secp256k1_gej) * (1 + 4 * runs));
    secp256k1_fe *zinv = (secp256k1_fe *)malloc(sizeof(secp256k1_fe) * (1 + 4 * runs));
    secp256k1_fe zf;
    secp256k1_fe zfi2, zfi3;

    secp256k1_gej_set_infinity(&gej[0]);
    secp256k1_ge_clear(&ge[0]);
    secp256k1_ge_set_gej_var(&ge[0], &gej[0]);
    for (i = 0; i < runs; i++) {
        int j;
        secp256k1_ge g;
        random_group_element_test(&g);
#ifdef USE_ENDOMORPHISM
        if (i >= runs - 2) {
            secp256k1_ge_mul_lambda(&g, &ge[1]);
        }
        if (i >= runs - 1) {
            secp256k1_ge_mul_lambda(&g, &g);
        }
#endif
        ge[1 + 4 * i] = g;
        ge[2 + 4 * i] = g;
        secp256k1_ge_neg(&ge[3 + 4 * i], &g);
        secp256k1_ge_neg(&ge[4 + 4 * i], &g);
        secp256k1_gej_set_ge(&gej[1 + 4 * i], &ge[1 + 4 * i]);
        random_group_element_jacobian_test(&gej[2 + 4 * i], &ge[2 + 4 * i]);
        secp256k1_gej_set_ge(&gej[3 + 4 * i], &ge[3 + 4 * i]);
        random_group_element_jacobian_test(&gej[4 + 4 * i], &ge[4 + 4 * i]);
        for (j = 0; j < 4; j++) {
            random_field_element_magnitude(&ge[1 + j + 4 * i].x);
            random_field_element_magnitude(&ge[1 + j + 4 * i].y);
            random_field_element_magnitude(&gej[1 + j + 4 * i].x);
            random_field_element_magnitude(&gej[1 + j + 4 * i].y);
            random_field_element_magnitude(&gej[1 + j + 4 * i].z);
        }
    }

    /* Compute z inverses. */
    {
        secp256k1_fe *zs = malloc(sizeof(secp256k1_fe) * (1 + 4 * runs));
        for (i = 0; i < 4 * runs + 1; i++) {
            if (i == 0) {
                /* The point at infinity does not have a meaningful z inverse. Any should do. */
                do {
                    random_field_element_test(&zs[i]);
                } while(secp256k1_fe_is_zero(&zs[i]));
            } else {
                zs[i] = gej[i].z;
            }
        }
        secp256k1_fe_inv_all_var(4 * runs + 1, zinv, zs);
        free(zs);
    }

    /* Generate random zf, and zfi2 = 1/zf^2, zfi3 = 1/zf^3 */
    do {
        random_field_element_test(&zf);
    } while(secp256k1_fe_is_zero(&zf));
    random_field_element_magnitude(&zf);
    secp256k1_fe_inv_var(&zfi3, &zf);
    secp256k1_fe_sqr(&zfi2, &zfi3);
    secp256k1_fe_mul(&zfi3, &zfi3, &zfi2);

    for (i1 = 0; i1 < 1 + 4 * runs; i1++) {
        int i2;
        for (i2 = 0; i2 < 1 + 4 * runs; i2++) {
            /* Compute reference result using gej + gej (var). */
            secp256k1_gej refj, resj;
            secp256k1_ge ref;
            secp256k1_fe zr;
            secp256k1_gej_add_var(&refj, &gej[i1], &gej[i2], secp256k1_gej_is_infinity(&gej[i1]) ? NULL : &zr);
            /* Check Z ratio. */
            if (!secp256k1_gej_is_infinity(&gej[i1]) && !secp256k1_gej_is_infinity(&refj)) {
                secp256k1_fe zrz; secp256k1_fe_mul(&zrz, &zr, &gej[i1].z);
                CHECK(secp256k1_fe_equal_var(&zrz, &refj.z));
            }
            secp256k1_ge_set_gej_var(&ref, &refj);

            /* Test gej + ge with Z ratio result (var). */
            secp256k1_gej_add_ge_var(&resj, &gej[i1], &ge[i2], secp256k1_gej_is_infinity(&gej[i1]) ? NULL : &zr);
            ge_equals_gej(&ref, &resj);
            if (!secp256k1_gej_is_infinity(&gej[i1]) && !secp256k1_gej_is_infinity(&resj)) {
                secp256k1_fe zrz; secp256k1_fe_mul(&zrz, &zr, &gej[i1].z);
                CHECK(secp256k1_fe_equal_var(&zrz, &resj.z));
            }

            /* Test gej + ge (var, with additional Z factor). */
            {
                secp256k1_ge ge2_zfi = ge[i2]; /* the second term with x and y rescaled for z = 1/zf */
                secp256k1_fe_mul(&ge2_zfi.x, &ge2_zfi.x, &zfi2);
                secp256k1_fe_mul(&ge2_zfi.y, &ge2_zfi.y, &zfi3);
                random_field_element_magnitude(&ge2_zfi.x);
                random_field_element_magnitude(&ge2_zfi.y);
                secp256k1_gej_add_zinv_var(&resj, &gej[i1], &ge2_zfi, &zf);
                ge_equals_gej(&ref, &resj);
            }

            /* Test gej + ge (const). */
            if (i2 != 0) {
                /* secp256k1_gej_add_ge does not support its second argument being infinity. */
                secp256k1_gej_add_ge(&resj, &gej[i1], &ge[i2]);
                ge_equals_gej(&ref, &resj);
            }

            /* Test doubling (var). */
            if ((i1 == 0 && i2 == 0) || ((i1 + 3)/4 == (i2 + 3)/4 && ((i1 + 3)%4)/2 == ((i2 + 3)%4)/2)) {
                secp256k1_fe zr2;
                /* Normal doubling with Z ratio result. */
                secp256k1_gej_double_var(&resj, &gej[i1], &zr2);
                ge_equals_gej(&ref, &resj);
                /* Check Z ratio. */
                secp256k1_fe_mul(&zr2, &zr2, &gej[i1].z);
                CHECK(secp256k1_fe_equal_var(&zr2, &resj.z));
                /* Normal doubling. */
                secp256k1_gej_double_var(&resj, &gej[i2], NULL);
                ge_equals_gej(&ref, &resj);
            }

            /* Test adding opposites. */
            if ((i1 == 0 && i2 == 0) || ((i1 + 3)/4 == (i2 + 3)/4 && ((i1 + 3)%4)/2 != ((i2 + 3)%4)/2)) {
                CHECK(secp256k1_ge_is_infinity(&ref));
            }

            /* Test adding infinity. */
            if (i1 == 0) {
                CHECK(secp256k1_ge_is_infinity(&ge[i1]));
                CHECK(secp256k1_gej_is_infinity(&gej[i1]));
                ge_equals_gej(&ref, &gej[i2]);
            }
            if (i2 == 0) {
                CHECK(secp256k1_ge_is_infinity(&ge[i2]));
                CHECK(secp256k1_gej_is_infinity(&gej[i2]));
                ge_equals_gej(&ref, &gej[i1]);
            }
        }
    }

    /* Test adding all points together in random order equals infinity. */
    {
        secp256k1_gej sum = SECP256K1_GEJ_CONST_INFINITY;
        secp256k1_gej *gej_shuffled = (secp256k1_gej *)malloc((4 * runs + 1) * sizeof(secp256k1_gej));
        for (i = 0; i < 4 * runs + 1; i++) {
            gej_shuffled[i] = gej[i];
        }
        for (i = 0; i < 4 * runs + 1; i++) {
            int swap = i + secp256k1_rand32() % (4 * runs + 1 - i);
            if (swap != i) {
                secp256k1_gej t = gej_shuffled[i];
                gej_shuffled[i] = gej_shuffled[swap];
                gej_shuffled[swap] = t;
            }
        }
        for (i = 0; i < 4 * runs + 1; i++) {
            secp256k1_gej_add_var(&sum, &sum, &gej_shuffled[i], NULL);
        }
        CHECK(secp256k1_gej_is_infinity(&sum));
        free(gej_shuffled);
    }

    /* Test batch gej -> ge conversion with and without known z ratios. */
    {
        secp256k1_fe *zr = (secp256k1_fe *)malloc((4 * runs + 1) * sizeof(secp256k1_fe));
        secp256k1_ge *ge_set_table = (secp256k1_ge *)malloc((4 * runs + 1) * sizeof(secp256k1_ge));
        secp256k1_ge *ge_set_all = (secp256k1_ge *)malloc((4 * runs + 1) * sizeof(secp256k1_ge));
        for (i = 0; i < 4 * runs + 1; i++) {
            /* Compute gej[i + 1].z / gez[i].z (with gej[n].z taken to be 1). */
            if (i < 4 * runs) {
                secp256k1_fe_mul(&zr[i + 1], &zinv[i], &gej[i + 1].z);
            }
        }
        secp256k1_ge_set_table_gej_var(4 * runs + 1, ge_set_table, gej, zr);
        secp256k1_ge_set_all_gej_var(4 * runs + 1, ge_set_all, gej, &ctx->error_callback);
        for (i = 0; i < 4 * runs + 1; i++) {
            secp256k1_fe s;
            random_fe_non_zero(&s);
            secp256k1_gej_rescale(&gej[i], &s);
            ge_equals_gej(&ge_set_table[i], &gej[i]);
            ge_equals_gej(&ge_set_all[i], &gej[i]);
        }
        free(ge_set_table);
        free(ge_set_all);
        free(zr);
    }

    free(ge);
    free(gej);
    free(zinv);
}

void test_add_neg_y_diff_x(void) {
    /* The point of this test is to check that we can add two points
     * whose y-coordinates are negatives of each other but whose x
     * coordinates differ. If the x-coordinates were the same, these
     * points would be negatives of each other and their sum is
     * infinity. This is cool because it "covers up" any degeneracy
     * in the addition algorithm that would cause the xy coordinates
     * of the sum to be wrong (since infinity has no xy coordinates).
     * HOWEVER, if the x-coordinates are different, infinity is the
     * wrong answer, and such degeneracies are exposed. This is the
     * root of https://github.com/bitcoin/secp256k1/issues/257 which
     * this test is a regression test for.
     *
     * These points were generated in sage as
     * # secp256k1 params
     * F = FiniteField (0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
     * C = EllipticCurve ([F (0), F (7)])
     * G = C.lift_x(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798)
     * N = FiniteField(G.order())
     *
     * # endomorphism values (lambda is 1^{1/3} in N, beta is 1^{1/3} in F)
     * x = polygen(N)
     * lam  = (1 - x^3).roots()[1][0]
     *
     * # random "bad pair"
     * P = C.random_element()
     * Q = -int(lam) * P
     * print "    P: %x %x" % P.xy()
     * print "    Q: %x %x" % Q.xy()
     * print "P + Q: %x %x" % (P + Q).xy()
     */
    secp256k1_gej aj = SECP256K1_GEJ_CONST(
        0x8d24cd95, 0x0a355af1, 0x3c543505, 0x44238d30,
        0x0643d79f, 0x05a59614, 0x2f8ec030, 0xd58977cb,
        0x001e337a, 0x38093dcd, 0x6c0f386d, 0x0b1293a8,
        0x4d72c879, 0xd7681924, 0x44e6d2f3, 0x9190117d
    );
    secp256k1_gej bj = SECP256K1_GEJ_CONST(
        0xc7b74206, 0x1f788cd9, 0xabd0937d, 0x164a0d86,
        0x95f6ff75, 0xf19a4ce9, 0xd013bd7b, 0xbf92d2a7,
        0xffe1cc85, 0xc7f6c232, 0x93f0c792, 0xf4ed6c57,
        0xb28d3786, 0x2897e6db, 0xbb192d0b, 0x6e6feab2
    );
    secp256k1_gej sumj = SECP256K1_GEJ_CONST(
        0x671a63c0, 0x3efdad4c, 0x389a7798, 0x24356027,
        0xb3d69010, 0x278625c3, 0x5c86d390, 0x184a8f7a,
        0x5f6409c2, 0x2ce01f2b, 0x511fd375, 0x25071d08,
        0xda651801, 0x70e95caf, 0x8f0d893c, 0xbed8fbbe
    );
    secp256k1_ge b;
    secp256k1_gej resj;
    secp256k1_ge res;
    secp256k1_ge_set_gej(&b, &bj);

    secp256k1_gej_add_var(&resj, &aj, &bj, NULL);
    secp256k1_ge_set_gej(&res, &resj);
    ge_equals_gej(&res, &sumj);

    secp256k1_gej_add_ge(&resj, &aj, &b);
    secp256k1_ge_set_gej(&res, &resj);
    ge_equals_gej(&res, &sumj);

    secp256k1_gej_add_ge_var(&resj, &aj, &b, NULL);
    secp256k1_ge_set_gej(&res, &resj);
    ge_equals_gej(&res, &sumj);
}

void run_ge(void) {
    int i;
    for (i = 0; i < count * 32; i++) {
        test_ge();
    }
    test_add_neg_y_diff_x();
}

void test_ec_combine(void) {
    secp256k1_scalar sum = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    secp256k1_pubkey data[6];
    const secp256k1_pubkey* d[6];
    secp256k1_pubkey sd;
    secp256k1_pubkey sd2;
    secp256k1_gej Qj;
    secp256k1_ge Q;
    int i;
    for (i = 1; i <= 6; i++) {
        secp256k1_scalar s;
        random_scalar_order_test(&s);
        secp256k1_scalar_add(&sum, &sum, &s);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &Qj, &s);
        secp256k1_ge_set_gej(&Q, &Qj);
        secp256k1_pubkey_save(&data[i - 1], &Q);
        d[i - 1] = &data[i - 1];
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &Qj, &sum);
        secp256k1_ge_set_gej(&Q, &Qj);
        secp256k1_pubkey_save(&sd, &Q);
        CHECK(secp256k1_ec_pubkey_combine(ctx, &sd2, d, i) == 1);
        CHECK(memcmp(&sd, &sd2, sizeof(sd)) == 0);
    }
}

void run_ec_combine(void) {
    int i;
    for (i = 0; i < count * 8; i++) {
         test_ec_combine();
    }
}

/***** ECMULT TESTS *****/

void run_ecmult_chain(void) {
    /* random starting point A (on the curve) */
    secp256k1_gej a = SECP256K1_GEJ_CONST(
        0x8b30bbe9, 0xae2a9906, 0x96b22f67, 0x0709dff3,
        0x727fd8bc, 0x04d3362c, 0x6c7bf458, 0xe2846004,
        0xa357ae91, 0x5c4a6528, 0x1309edf2, 0x0504740f,
        0x0eb33439, 0x90216b4f, 0x81063cb6, 0x5f2f7e0f
    );
    /* two random initial factors xn and gn */
    secp256k1_scalar xn = SECP256K1_SCALAR_CONST(
        0x84cc5452, 0xf7fde1ed, 0xb4d38a8c, 0xe9b1b84c,
        0xcef31f14, 0x6e569be9, 0x705d357a, 0x42985407
    );
    secp256k1_scalar gn = SECP256K1_SCALAR_CONST(
        0xa1e58d22, 0x553dcd42, 0xb2398062, 0x5d4c57a9,
        0x6e9323d4, 0x2b3152e5, 0xca2c3990, 0xedc7c9de
    );
    /* two small multipliers to be applied to xn and gn in every iteration: */
    static const secp256k1_scalar xf = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0x1337);
    static const secp256k1_scalar gf = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0x7113);
    /* accumulators with the resulting coefficients to A and G */
    secp256k1_scalar ae = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    secp256k1_scalar ge = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    /* actual points */
    secp256k1_gej x;
    secp256k1_gej x2;
    int i;

    /* the point being computed */
    x = a;
    for (i = 0; i < 200*count; i++) {
        /* in each iteration, compute X = xn*X + gn*G; */
        secp256k1_ecmult(&ctx->ecmult_ctx, &x, &x, &xn, &gn);
        /* also compute ae and ge: the actual accumulated factors for A and G */
        /* if X was (ae*A+ge*G), xn*X + gn*G results in (xn*ae*A + (xn*ge+gn)*G) */
        secp256k1_scalar_mul(&ae, &ae, &xn);
        secp256k1_scalar_mul(&ge, &ge, &xn);
        secp256k1_scalar_add(&ge, &ge, &gn);
        /* modify xn and gn */
        secp256k1_scalar_mul(&xn, &xn, &xf);
        secp256k1_scalar_mul(&gn, &gn, &gf);

        /* verify */
        if (i == 19999) {
            /* expected result after 19999 iterations */
            secp256k1_gej rp = SECP256K1_GEJ_CONST(
                0xD6E96687, 0xF9B10D09, 0x2A6F3543, 0x9D86CEBE,
                0xA4535D0D, 0x409F5358, 0x6440BD74, 0xB933E830,
                0xB95CBCA2, 0xC77DA786, 0x539BE8FD, 0x53354D2D,
                0x3B4F566A, 0xE6580454, 0x07ED6015, 0xEE1B2A88
            );

            secp256k1_gej_neg(&rp, &rp);
            secp256k1_gej_add_var(&rp, &rp, &x, NULL);
            CHECK(secp256k1_gej_is_infinity(&rp));
        }
    }
    /* redo the computation, but directly with the resulting ae and ge coefficients: */
    secp256k1_ecmult(&ctx->ecmult_ctx, &x2, &a, &ae, &ge);
    secp256k1_gej_neg(&x2, &x2);
    secp256k1_gej_add_var(&x2, &x2, &x, NULL);
    CHECK(secp256k1_gej_is_infinity(&x2));
}

void test_point_times_order(const secp256k1_gej *point) {
    /* X * (point + G) + (order-X) * (pointer + G) = 0 */
    secp256k1_scalar x;
    secp256k1_scalar nx;
    secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    secp256k1_scalar one = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    secp256k1_gej res1, res2;
    secp256k1_ge res3;
    unsigned char pub[65];
    size_t psize = 65;
    random_scalar_order_test(&x);
    secp256k1_scalar_negate(&nx, &x);
    secp256k1_ecmult(&ctx->ecmult_ctx, &res1, point, &x, &x); /* calc res1 = x * point + x * G; */
    secp256k1_ecmult(&ctx->ecmult_ctx, &res2, point, &nx, &nx); /* calc res2 = (order - x) * point + (order - x) * G; */
    secp256k1_gej_add_var(&res1, &res1, &res2, NULL);
    CHECK(secp256k1_gej_is_infinity(&res1));
    CHECK(secp256k1_gej_is_valid_var(&res1) == 0);
    secp256k1_ge_set_gej(&res3, &res1);
    CHECK(secp256k1_ge_is_infinity(&res3));
    CHECK(secp256k1_ge_is_valid_var(&res3) == 0);
    CHECK(secp256k1_eckey_pubkey_serialize(&res3, pub, &psize, 0) == 0);
    psize = 65;
    CHECK(secp256k1_eckey_pubkey_serialize(&res3, pub, &psize, 1) == 0);
    /* check zero/one edge cases */
    secp256k1_ecmult(&ctx->ecmult_ctx, &res1, point, &zero, &zero);
    secp256k1_ge_set_gej(&res3, &res1);
    CHECK(secp256k1_ge_is_infinity(&res3));
    secp256k1_ecmult(&ctx->ecmult_ctx, &res1, point, &one, &zero);
    secp256k1_ge_set_gej(&res3, &res1);
    ge_equals_gej(&res3, point);
    secp256k1_ecmult(&ctx->ecmult_ctx, &res1, point, &zero, &one);
    secp256k1_ge_set_gej(&res3, &res1);
    ge_equals_ge(&res3, &secp256k1_ge_const_g);
}

void run_point_times_order(void) {
    int i;
    secp256k1_fe x = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 2);
    static const secp256k1_fe xr = SECP256K1_FE_CONST(
        0x7603CB59, 0xB0EF6C63, 0xFE608479, 0x2A0C378C,
        0xDB3233A8, 0x0F8A9A09, 0xA877DEAD, 0x31B38C45
    );
    for (i = 0; i < 500; i++) {
        secp256k1_ge p;
        if (secp256k1_ge_set_xo_var(&p, &x, 1)) {
            secp256k1_gej j;
            CHECK(secp256k1_ge_is_valid_var(&p));
            secp256k1_gej_set_ge(&j, &p);
            CHECK(secp256k1_gej_is_valid_var(&j));
            test_point_times_order(&j);
        }
        secp256k1_fe_sqr(&x, &x);
    }
    secp256k1_fe_normalize_var(&x);
    CHECK(secp256k1_fe_equal_var(&x, &xr));
}

void ecmult_const_random_mult(void) {
    /* random starting point A (on the curve) */
    secp256k1_ge a = SECP256K1_GE_CONST(
        0x6d986544, 0x57ff52b8, 0xcf1b8126, 0x5b802a5b,
        0xa97f9263, 0xb1e88044, 0x93351325, 0x91bc450a,
        0x535c59f7, 0x325e5d2b, 0xc391fbe8, 0x3c12787c,
        0x337e4a98, 0xe82a9011, 0x0123ba37, 0xdd769c7d
    );
    /* random initial factor xn */
    secp256k1_scalar xn = SECP256K1_SCALAR_CONST(
        0x649d4f77, 0xc4242df7, 0x7f2079c9, 0x14530327,
        0xa31b876a, 0xd2d8ce2a, 0x2236d5c6, 0xd7b2029b
    );
    /* expected xn * A (from sage) */
    secp256k1_ge expected_b = SECP256K1_GE_CONST(
        0x23773684, 0x4d209dc7, 0x098a786f, 0x20d06fcd,
        0x070a38bf, 0xc11ac651, 0x03004319, 0x1e2a8786,
        0xed8c3b8e, 0xc06dd57b, 0xd06ea66e, 0x45492b0f,
        0xb84e4e1b, 0xfb77e21f, 0x96baae2a, 0x63dec956
    );
    secp256k1_gej b;
    secp256k1_ecmult_const(&b, &a, &xn);

    CHECK(secp256k1_ge_is_valid_var(&a));
    ge_equals_gej(&expected_b, &b);
}

void ecmult_const_commutativity(void) {
    secp256k1_scalar a;
    secp256k1_scalar b;
    secp256k1_gej res1;
    secp256k1_gej res2;
    secp256k1_ge mid1;
    secp256k1_ge mid2;
    random_scalar_order_test(&a);
    random_scalar_order_test(&b);

    secp256k1_ecmult_const(&res1, &secp256k1_ge_const_g, &a);
    secp256k1_ecmult_const(&res2, &secp256k1_ge_const_g, &b);
    secp256k1_ge_set_gej(&mid1, &res1);
    secp256k1_ge_set_gej(&mid2, &res2);
    secp256k1_ecmult_const(&res1, &mid1, &b);
    secp256k1_ecmult_const(&res2, &mid2, &a);
    secp256k1_ge_set_gej(&mid1, &res1);
    secp256k1_ge_set_gej(&mid2, &res2);
    ge_equals_ge(&mid1, &mid2);
}

void ecmult_const_mult_zero_one(void) {
    secp256k1_scalar zero = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    secp256k1_scalar one = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    secp256k1_scalar negone;
    secp256k1_gej res1;
    secp256k1_ge res2;
    secp256k1_ge point;
    secp256k1_scalar_negate(&negone, &one);

    random_group_element_test(&point);
    secp256k1_ecmult_const(&res1, &point, &zero);
    secp256k1_ge_set_gej(&res2, &res1);
    CHECK(secp256k1_ge_is_infinity(&res2));
    secp256k1_ecmult_const(&res1, &point, &one);
    secp256k1_ge_set_gej(&res2, &res1);
    ge_equals_ge(&res2, &point);
    secp256k1_ecmult_const(&res1, &point, &negone);
    secp256k1_gej_neg(&res1, &res1);
    secp256k1_ge_set_gej(&res2, &res1);
    ge_equals_ge(&res2, &point);
}

void ecmult_const_chain_multiply(void) {
    /* Check known result (randomly generated test problem from sage) */
    const secp256k1_scalar scalar = SECP256K1_SCALAR_CONST(
        0x4968d524, 0x2abf9b7a, 0x466abbcf, 0x34b11b6d,
        0xcd83d307, 0x827bed62, 0x05fad0ce, 0x18fae63b
    );
    const secp256k1_gej expected_point = SECP256K1_GEJ_CONST(
        0x5494c15d, 0x32099706, 0xc2395f94, 0x348745fd,
        0x757ce30e, 0x4e8c90fb, 0xa2bad184, 0xf883c69f,
        0x5d195d20, 0xe191bf7f, 0x1be3e55f, 0x56a80196,
        0x6071ad01, 0xf1462f66, 0xc997fa94, 0xdb858435
    );
    secp256k1_gej point;
    secp256k1_ge res;
    int i;

    secp256k1_gej_set_ge(&point, &secp256k1_ge_const_g);
    for (i = 0; i < 100; ++i) {
        secp256k1_ge tmp;
        secp256k1_ge_set_gej(&tmp, &point);
        secp256k1_ecmult_const(&point, &tmp, &scalar);
    }
    secp256k1_ge_set_gej(&res, &point);
    ge_equals_gej(&res, &expected_point);
}

void run_ecmult_const_tests(void) {
    ecmult_const_mult_zero_one();
    ecmult_const_random_mult();
    ecmult_const_commutativity();
    ecmult_const_chain_multiply();
}

void test_wnaf(const secp256k1_scalar *number, int w) {
    secp256k1_scalar x, two, t;
    int wnaf[256];
    int zeroes = -1;
    int i;
    int bits;
    secp256k1_scalar_set_int(&x, 0);
    secp256k1_scalar_set_int(&two, 2);
    bits = secp256k1_ecmult_wnaf(wnaf, 256, number, w);
    CHECK(bits <= 256);
    for (i = bits-1; i >= 0; i--) {
        int v = wnaf[i];
        secp256k1_scalar_mul(&x, &x, &two);
        if (v) {
            CHECK(zeroes == -1 || zeroes >= w-1); /* check that distance between non-zero elements is at least w-1 */
            zeroes=0;
            CHECK((v & 1) == 1); /* check non-zero elements are odd */
            CHECK(v <= (1 << (w-1)) - 1); /* check range below */
            CHECK(v >= -(1 << (w-1)) - 1); /* check range above */
        } else {
            CHECK(zeroes != -1); /* check that no unnecessary zero padding exists */
            zeroes++;
        }
        if (v >= 0) {
            secp256k1_scalar_set_int(&t, v);
        } else {
            secp256k1_scalar_set_int(&t, -v);
            secp256k1_scalar_negate(&t, &t);
        }
        secp256k1_scalar_add(&x, &x, &t);
    }
    CHECK(secp256k1_scalar_eq(&x, number)); /* check that wnaf represents number */
}

void test_constant_wnaf_negate(const secp256k1_scalar *number) {
    secp256k1_scalar neg1 = *number;
    secp256k1_scalar neg2 = *number;
    int sign1 = 1;
    int sign2 = 1;

    if (!secp256k1_scalar_get_bits(&neg1, 0, 1)) {
        secp256k1_scalar_negate(&neg1, &neg1);
        sign1 = -1;
    }
    sign2 = secp256k1_scalar_cond_negate(&neg2, secp256k1_scalar_is_even(&neg2));
    CHECK(sign1 == sign2);
    CHECK(secp256k1_scalar_eq(&neg1, &neg2));
}

void test_constant_wnaf(const secp256k1_scalar *number, int w) {
    secp256k1_scalar x, shift;
    int wnaf[256] = {0};
    int i;
#ifdef USE_ENDOMORPHISM
    int skew;
#endif
    secp256k1_scalar num = *number;

    secp256k1_scalar_set_int(&x, 0);
    secp256k1_scalar_set_int(&shift, 1 << w);
    /* With USE_ENDOMORPHISM on we only consider 128-bit numbers */
#ifdef USE_ENDOMORPHISM
    for (i = 0; i < 16; ++i) {
        secp256k1_scalar_shr_int(&num, 8);
    }
    skew = secp256k1_wnaf_const(wnaf, num, w);
#else
    secp256k1_wnaf_const(wnaf, num, w);
#endif

    for (i = WNAF_SIZE(w); i >= 0; --i) {
        secp256k1_scalar t;
        int v = wnaf[i];
        CHECK(v != 0); /* check nonzero */
        CHECK(v & 1);  /* check parity */
        CHECK(v > -(1 << w)); /* check range above */
        CHECK(v < (1 << w));  /* check range below */

        secp256k1_scalar_mul(&x, &x, &shift);
        if (v >= 0) {
            secp256k1_scalar_set_int(&t, v);
        } else {
            secp256k1_scalar_set_int(&t, -v);
            secp256k1_scalar_negate(&t, &t);
        }
        secp256k1_scalar_add(&x, &x, &t);
    }
#ifdef USE_ENDOMORPHISM
    /* Skew num because when encoding 128-bit numbers as odd we use an offset */
    secp256k1_scalar_cadd_bit(&num, skew == 2, 1);
#endif
    CHECK(secp256k1_scalar_eq(&x, &num));
}

void run_wnaf(void) {
    int i;
    secp256k1_scalar n = {{0}};

    /* Sanity check: 1 and 2 are the smallest odd and even numbers and should
     *               have easier-to-diagnose failure modes  */
    n.d[0] = 1;
    test_constant_wnaf(&n, 4);
    n.d[0] = 2;
    test_constant_wnaf(&n, 4);
    /* Random tests */
    for (i = 0; i < count; i++) {
        random_scalar_order(&n);
        test_wnaf(&n, 4+(i%10));
        test_constant_wnaf_negate(&n);
        test_constant_wnaf(&n, 4 + (i % 10));
    }
}

void test_ecmult_constants(void) {
    /* Test ecmult_gen() for [0..36) and [order-36..0). */
    secp256k1_scalar x;
    secp256k1_gej r;
    secp256k1_ge ng;
    int i;
    int j;
    secp256k1_ge_neg(&ng, &secp256k1_ge_const_g);
    for (i = 0; i < 36; i++ ) {
        secp256k1_scalar_set_int(&x, i);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &r, &x);
        for (j = 0; j < i; j++) {
            if (j == i - 1) {
                ge_equals_gej(&secp256k1_ge_const_g, &r);
            }
            secp256k1_gej_add_ge(&r, &r, &ng);
        }
        CHECK(secp256k1_gej_is_infinity(&r));
    }
    for (i = 1; i <= 36; i++ ) {
        secp256k1_scalar_set_int(&x, i);
        secp256k1_scalar_negate(&x, &x);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &r, &x);
        for (j = 0; j < i; j++) {
            if (j == i - 1) {
                ge_equals_gej(&ng, &r);
            }
            secp256k1_gej_add_ge(&r, &r, &secp256k1_ge_const_g);
        }
        CHECK(secp256k1_gej_is_infinity(&r));
    }
}

void run_ecmult_constants(void) {
    test_ecmult_constants();
}

void test_ecmult_gen_blind(void) {
    /* Test ecmult_gen() blinding and confirm that the blinding changes, the affline points match, and the z's don't match. */
    secp256k1_scalar key;
    secp256k1_scalar b;
    unsigned char seed32[32];
    secp256k1_gej pgej;
    secp256k1_gej pgej2;
    secp256k1_gej i;
    secp256k1_ge pge;
    random_scalar_order_test(&key);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pgej, &key);
    secp256k1_rand256(seed32);
    b = ctx->ecmult_gen_ctx.blind;
    i = ctx->ecmult_gen_ctx.initial;
    secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, seed32);
    CHECK(!secp256k1_scalar_eq(&b, &ctx->ecmult_gen_ctx.blind));
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pgej2, &key);
    CHECK(!gej_xyz_equals_gej(&pgej, &pgej2));
    CHECK(!gej_xyz_equals_gej(&i, &ctx->ecmult_gen_ctx.initial));
    secp256k1_ge_set_gej(&pge, &pgej);
    ge_equals_gej(&pge, &pgej2);
}

void test_ecmult_gen_blind_reset(void) {
    /* Test ecmult_gen() blinding reset and confirm that the blinding is consistent. */
    secp256k1_scalar b;
    secp256k1_gej initial;
    secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, 0);
    b = ctx->ecmult_gen_ctx.blind;
    initial = ctx->ecmult_gen_ctx.initial;
    secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, 0);
    CHECK(secp256k1_scalar_eq(&b, &ctx->ecmult_gen_ctx.blind));
    CHECK(gej_xyz_equals_gej(&initial, &ctx->ecmult_gen_ctx.initial));
}

void run_ecmult_gen_blind(void) {
    int i;
    test_ecmult_gen_blind_reset();
    for (i = 0; i < 10; i++) {
        test_ecmult_gen_blind();
    }
}

#ifdef USE_ENDOMORPHISM
/***** ENDOMORPHISH TESTS *****/
void test_scalar_split(void) {
    secp256k1_scalar full;
    secp256k1_scalar s1, slam;
    const unsigned char zero[32] = {0};
    unsigned char tmp[32];

    random_scalar_order_test(&full);
    secp256k1_scalar_split_lambda(&s1, &slam, &full);

    /* check that both are <= 128 bits in size */
    if (secp256k1_scalar_is_high(&s1)) {
        secp256k1_scalar_negate(&s1, &s1);
    }
    if (secp256k1_scalar_is_high(&slam)) {
        secp256k1_scalar_negate(&slam, &slam);
    }

    secp256k1_scalar_get_b32(tmp, &s1);
    CHECK(memcmp(zero, tmp, 16) == 0);
    secp256k1_scalar_get_b32(tmp, &slam);
    CHECK(memcmp(zero, tmp, 16) == 0);
}

void run_endomorphism_tests(void) {
    test_scalar_split();
}
#endif

static void counting_illegal_callback_fn(const char* str, void* data) {
    /* Dummy callback function that just counts. */
    int32_t *p;
    (void)str;
    p = data;
    (*p)++;
}

static void uncounting_illegal_callback_fn(const char* str, void* data) {
    /* Dummy callback function that just counts (backwards). */
    int32_t *p;
    (void)str;
    p = data;
    (*p)--;
}

void ec_pubkey_parse_pointtest(const unsigned char *input, int xvalid, int yvalid) {
    unsigned char pubkeyc[65];
    secp256k1_pubkey pubkey;
    secp256k1_ge ge;
    size_t pubkeyclen;
    int32_t ecount;
    ecount = 0;
    secp256k1_context_set_illegal_callback(ctx, counting_illegal_callback_fn, &ecount);
    for (pubkeyclen = 3; pubkeyclen <= 65; pubkeyclen++) {
        /* Smaller sizes are tested exhaustively elsewhere. */
        int32_t i;
        memcpy(&pubkeyc[1], input, 64);
        VG_UNDEF(&pubkeyc[pubkeyclen], 65 - pubkeyclen);
        for (i = 0; i < 256; i++) {
            /* Try all type bytes. */
            int xpass;
            int ypass;
            int ysign;
            pubkeyc[0] = i;
            /* What sign does this point have? */
            ysign = (input[63] & 1) + 2;
            /* For the current type (i) do we expect parsing to work? Handled all of compressed/uncompressed/hybrid. */
            xpass = xvalid && (pubkeyclen == 33) && ((i & 254) == 2);
            /* Do we expect a parse and re-serialize as uncompressed to give a matching y? */
            ypass = xvalid && yvalid && ((i & 4) == ((pubkeyclen == 65) << 2)) &&
                ((i == 4) || ((i & 251) == ysign)) && ((pubkeyclen == 33) || (pubkeyclen == 65));
            if (xpass || ypass) {
                /* These cases must parse. */
                unsigned char pubkeyo[65];
                size_t outl;
                memset(&pubkey, 0, sizeof(pubkey));
                VG_UNDEF(&pubkey, sizeof(pubkey));
                ecount = 0;
                CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == 1);
                VG_CHECK(&pubkey, sizeof(pubkey));
                outl = 65;
                VG_UNDEF(pubkeyo, 65);
                CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkeyo, &outl, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
                VG_CHECK(pubkeyo, outl);
                CHECK(outl == 33);
                CHECK(memcmp(&pubkeyo[1], &pubkeyc[1], 32) == 0);
                CHECK((pubkeyclen != 33) || (pubkeyo[0] == pubkeyc[0]));
                if (ypass) {
                    /* This test isn't always done because we decode with alternative signs, so the y won't match. */
                    CHECK(pubkeyo[0] == ysign);
                    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 1);
                    memset(&pubkey, 0, sizeof(pubkey));
                    VG_UNDEF(&pubkey, sizeof(pubkey));
                    secp256k1_pubkey_save(&pubkey, &ge);
                    VG_CHECK(&pubkey, sizeof(pubkey));
                    outl = 65;
                    VG_UNDEF(pubkeyo, 65);
                    CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkeyo, &outl, &pubkey, 0) == 1);
                    VG_CHECK(pubkeyo, outl);
                    CHECK(outl == 65);
                    CHECK(pubkeyo[0] == 4);
                    CHECK(memcmp(&pubkeyo[1], input, 64) == 0);
                }
                CHECK(ecount == 0);
            } else {
                /* These cases must fail to parse. */
                memset(&pubkey, 0xfe, sizeof(pubkey));
                ecount = 0;
                VG_UNDEF(&pubkey, sizeof(pubkey));
                CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == 0);
                VG_CHECK(&pubkey, sizeof(pubkey));
                CHECK(ecount == 0);
                CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
                CHECK(ecount == 1);
            }
        }
    }
    secp256k1_context_set_illegal_callback(ctx, NULL, NULL);
}

void run_ec_pubkey_parse_test(void) {
#define SECP256K1_EC_PARSE_TEST_NVALID (12)
    const unsigned char valid[SECP256K1_EC_PARSE_TEST_NVALID][64] = {
        {
            /* Point with leading and trailing zeros in x and y serialization. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x52,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x64, 0xef, 0xa1, 0x7b, 0x77, 0x61, 0xe1, 0xe4, 0x27, 0x06, 0x98, 0x9f, 0xb4, 0x83,
            0xb8, 0xd2, 0xd4, 0x9b, 0xf7, 0x8f, 0xae, 0x98, 0x03, 0xf0, 0x99, 0xb8, 0x34, 0xed, 0xeb, 0x00
        },
        {
            /* Point with x equal to a 3rd root of unity.*/
            0x7a, 0xe9, 0x6a, 0x2b, 0x65, 0x7c, 0x07, 0x10, 0x6e, 0x64, 0x47, 0x9e, 0xac, 0x34, 0x34, 0xe9,
            0x9c, 0xf0, 0x49, 0x75, 0x12, 0xf5, 0x89, 0x95, 0xc1, 0x39, 0x6c, 0x28, 0x71, 0x95, 0x01, 0xee,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        },
        {
            /* Point with largest x. (1/2) */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
            0x0e, 0x99, 0x4b, 0x14, 0xea, 0x72, 0xf8, 0xc3, 0xeb, 0x95, 0xc7, 0x1e, 0xf6, 0x92, 0x57, 0x5e,
            0x77, 0x50, 0x58, 0x33, 0x2d, 0x7e, 0x52, 0xd0, 0x99, 0x5c, 0xf8, 0x03, 0x88, 0x71, 0xb6, 0x7d,
        },
        {
            /* Point with largest x. (2/2) */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2c,
            0xf1, 0x66, 0xb4, 0xeb, 0x15, 0x8d, 0x07, 0x3c, 0x14, 0x6a, 0x38, 0xe1, 0x09, 0x6d, 0xa8, 0xa1,
            0x88, 0xaf, 0xa7, 0xcc, 0xd2, 0x81, 0xad, 0x2f, 0x66, 0xa3, 0x07, 0xfb, 0x77, 0x8e, 0x45, 0xb2,
        },
        {
            /* Point with smallest x. (1/2) */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        },
        {
            /* Point with smallest x. (2/2) */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0xbd, 0xe7, 0x0d, 0xf5, 0x19, 0x39, 0xb9, 0x4c, 0x9c, 0x24, 0x97, 0x9f, 0xa7, 0xdd, 0x04, 0xeb,
            0xd9, 0xb3, 0x57, 0x2d, 0xa7, 0x80, 0x22, 0x90, 0x43, 0x8a, 0xf2, 0xa6, 0x81, 0x89, 0x54, 0x41,
        },
        {
            /* Point with largest y. (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        },
        {
            /* Point with largest y. (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        },
        {
            /* Point with largest y. (3/3) */
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
        },
        {
            /* Point with smallest y. (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
        {
            /* Point with smallest y. (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
        {
            /* Point with smallest y. (3/3) */
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        }
    };
#define SECP256K1_EC_PARSE_TEST_NXVALID (4)
    const unsigned char onlyxvalid[SECP256K1_EC_PARSE_TEST_NXVALID][64] = {
        {
            /* Valid if y overflow ignored (y = 1 mod p). (1/3) */
            0x1f, 0xe1, 0xe5, 0xef, 0x3f, 0xce, 0xb5, 0xc1, 0x35, 0xab, 0x77, 0x41, 0x33, 0x3c, 0xe5, 0xa6,
            0xe8, 0x0d, 0x68, 0x16, 0x76, 0x53, 0xf6, 0xb2, 0xb2, 0x4b, 0xcb, 0xcf, 0xaa, 0xaf, 0xf5, 0x07,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        },
        {
            /* Valid if y overflow ignored (y = 1 mod p). (2/3) */
            0xcb, 0xb0, 0xde, 0xab, 0x12, 0x57, 0x54, 0xf1, 0xfd, 0xb2, 0x03, 0x8b, 0x04, 0x34, 0xed, 0x9c,
            0xb3, 0xfb, 0x53, 0xab, 0x73, 0x53, 0x91, 0x12, 0x99, 0x94, 0xa5, 0x35, 0xd9, 0x25, 0xf6, 0x73,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        },
        {
            /* Valid if y overflow ignored (y = 1 mod p). (3/3)*/
            0x14, 0x6d, 0x3b, 0x65, 0xad, 0xd9, 0xf5, 0x4c, 0xcc, 0xa2, 0x85, 0x33, 0xc8, 0x8e, 0x2c, 0xbc,
            0x63, 0xf7, 0x44, 0x3e, 0x16, 0x58, 0x78, 0x3a, 0xb4, 0x1f, 0x8e, 0xf9, 0x7c, 0x2a, 0x10, 0xb5,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
        },
        {
            /* x on curve, y is from y^2 = x^3 + 8. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03
        }
    };
#define SECP256K1_EC_PARSE_TEST_NINVALID (7)
    const unsigned char invalid[SECP256K1_EC_PARSE_TEST_NINVALID][64] = {
        {
            /* x is third root of -8, y is -1 * (x^3+7); also on the curve for y^2 = x^3 + 9. */
            0x0a, 0x2d, 0x2b, 0xa9, 0x35, 0x07, 0xf1, 0xdf, 0x23, 0x37, 0x70, 0xc2, 0xa7, 0x97, 0x96, 0x2c,
            0xc6, 0x1f, 0x6d, 0x15, 0xda, 0x14, 0xec, 0xd4, 0x7d, 0x8d, 0x27, 0xae, 0x1c, 0xd5, 0xf8, 0x53,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        },
        {
            /* Valid if x overflow ignored (x = 1 mod p). */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
            0x42, 0x18, 0xf2, 0x0a, 0xe6, 0xc6, 0x46, 0xb3, 0x63, 0xdb, 0x68, 0x60, 0x58, 0x22, 0xfb, 0x14,
            0x26, 0x4c, 0xa8, 0xd2, 0x58, 0x7f, 0xdd, 0x6f, 0xbc, 0x75, 0x0d, 0x58, 0x7e, 0x76, 0xa7, 0xee,
        },
        {
            /* Valid if x overflow ignored (x = 1 mod p). */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x30,
            0xbd, 0xe7, 0x0d, 0xf5, 0x19, 0x39, 0xb9, 0x4c, 0x9c, 0x24, 0x97, 0x9f, 0xa7, 0xdd, 0x04, 0xeb,
            0xd9, 0xb3, 0x57, 0x2d, 0xa7, 0x80, 0x22, 0x90, 0x43, 0x8a, 0xf2, 0xa6, 0x81, 0x89, 0x54, 0x41,
        },
        {
            /* x is -1, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 5. */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
            0xf4, 0x84, 0x14, 0x5c, 0xb0, 0x14, 0x9b, 0x82, 0x5d, 0xff, 0x41, 0x2f, 0xa0, 0x52, 0xa8, 0x3f,
            0xcb, 0x72, 0xdb, 0x61, 0xd5, 0x6f, 0x37, 0x70, 0xce, 0x06, 0x6b, 0x73, 0x49, 0xa2, 0xaa, 0x28,
        },
        {
            /* x is -1, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 5. */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2e,
            0x0b, 0x7b, 0xeb, 0xa3, 0x4f, 0xeb, 0x64, 0x7d, 0xa2, 0x00, 0xbe, 0xd0, 0x5f, 0xad, 0x57, 0xc0,
            0x34, 0x8d, 0x24, 0x9e, 0x2a, 0x90, 0xc8, 0x8f, 0x31, 0xf9, 0x94, 0x8b, 0xb6, 0x5d, 0x52, 0x07,
        },
        {
            /* x is zero, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 7. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x8f, 0x53, 0x7e, 0xef, 0xdf, 0xc1, 0x60, 0x6a, 0x07, 0x27, 0xcd, 0x69, 0xb4, 0xa7, 0x33, 0x3d,
            0x38, 0xed, 0x44, 0xe3, 0x93, 0x2a, 0x71, 0x79, 0xee, 0xcb, 0x4b, 0x6f, 0xba, 0x93, 0x60, 0xdc,
        },
        {
            /* x is zero, y is the result of the sqrt ladder; also on the curve for y^2 = x^3 - 7. */
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x70, 0xac, 0x81, 0x10, 0x20, 0x3e, 0x9f, 0x95, 0xf8, 0xd8, 0x32, 0x96, 0x4b, 0x58, 0xcc, 0xc2,
            0xc7, 0x12, 0xbb, 0x1c, 0x6c, 0xd5, 0x8e, 0x86, 0x11, 0x34, 0xb4, 0x8f, 0x45, 0x6c, 0x9b, 0x53
        }
    };
    const unsigned char pubkeyc[66] = {
        /* Serialization of G. */
        0x04, 0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17,
        0x98, 0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65, 0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08,
        0xA8, 0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19, 0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4,
        0xB8, 0x00
    };
    unsigned char shortkey[2];
    secp256k1_ge ge;
    secp256k1_pubkey pubkey;
    int32_t i;
    int32_t ecount;
    int32_t ecount2;
    ecount = 0;
    /* Nothing should be reading this far into pubkeyc. */
    VG_UNDEF(&pubkeyc[65], 1);
    secp256k1_context_set_illegal_callback(ctx, counting_illegal_callback_fn, &ecount);
    /* Zero length claimed, fail, zeroize, no illegal arg error. */
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    VG_UNDEF(shortkey, 2);
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 0) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 1);
    /* Length one claimed, fail, zeroize, no illegal arg error. */
    for (i = 0; i < 256 ; i++) {
        memset(&pubkey, 0xfe, sizeof(pubkey));
        ecount = 0;
        shortkey[0] = i;
        VG_UNDEF(&shortkey[1], 1);
        VG_UNDEF(&pubkey, sizeof(pubkey));
        CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 1) == 0);
        VG_CHECK(&pubkey, sizeof(pubkey));
        CHECK(ecount == 0);
        CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
        CHECK(ecount == 1);
    }
    /* Length two claimed, fail, zeroize, no illegal arg error. */
    for (i = 0; i < 65536 ; i++) {
        memset(&pubkey, 0xfe, sizeof(pubkey));
        ecount = 0;
        shortkey[0] = i & 255;
        shortkey[1] = i >> 8;
        VG_UNDEF(&pubkey, sizeof(pubkey));
        CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, shortkey, 2) == 0);
        VG_CHECK(&pubkey, sizeof(pubkey));
        CHECK(ecount == 0);
        CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
        CHECK(ecount == 1);
    }
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    VG_UNDEF(&pubkey, sizeof(pubkey));
    /* 33 bytes claimed on otherwise valid input starting with 0x04, fail, zeroize output, no illegal arg error. */
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 33) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 1);
    /* NULL pubkey, illegal arg error. Pubkey isn't rewritten before this step, since it's NULL into the parser. */
    CHECK(secp256k1_ec_pubkey_parse(ctx, NULL, pubkeyc, 65) == 0);
    CHECK(ecount == 2);
    /* NULL input string. Illegal arg and zeroize output. */
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, NULL, 65) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 1);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 2);
    /* 64 bytes claimed on input starting with 0x04, fail, zeroize output, no illegal arg error. */
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 64) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 1);
    /* 66 bytes claimed, fail, zeroize output, no illegal arg error. */
    memset(&pubkey, 0xfe, sizeof(pubkey));
    ecount = 0;
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 66) == 0);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 0);
    CHECK(ecount == 1);
    /* Valid parse. */
    memset(&pubkey, 0, sizeof(pubkey));
    ecount = 0;
    VG_UNDEF(&pubkey, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, 65) == 1);
    VG_CHECK(&pubkey, sizeof(pubkey));
    CHECK(ecount == 0);
    VG_UNDEF(&ge, sizeof(ge));
    CHECK(secp256k1_pubkey_load(ctx, &ge, &pubkey) == 1);
    VG_CHECK(&ge.x, sizeof(ge.x));
    VG_CHECK(&ge.y, sizeof(ge.y));
    VG_CHECK(&ge.infinity, sizeof(ge.infinity));
    ge_equals_ge(&secp256k1_ge_const_g, &ge);
    CHECK(ecount == 0);
    /* Multiple illegal args. Should still set arg error only once. */
    ecount = 0;
    ecount2 = 11;
    CHECK(secp256k1_ec_pubkey_parse(ctx, NULL, NULL, 65) == 0);
    CHECK(ecount == 1);
    /* Does the illegal arg callback actually change the behavior? */
    secp256k1_context_set_illegal_callback(ctx, uncounting_illegal_callback_fn, &ecount2);
    CHECK(secp256k1_ec_pubkey_parse(ctx, NULL, NULL, 65) == 0);
    CHECK(ecount == 1);
    CHECK(ecount2 == 10);
    secp256k1_context_set_illegal_callback(ctx, NULL, NULL);
    /* Try a bunch of prefabbed points with all possible encodings. */
    for (i = 0; i < SECP256K1_EC_PARSE_TEST_NVALID; i++) {
        ec_pubkey_parse_pointtest(valid[i], 1, 1);
    }
    for (i = 0; i < SECP256K1_EC_PARSE_TEST_NXVALID; i++) {
        ec_pubkey_parse_pointtest(onlyxvalid[i], 1, 0);
    }
    for (i = 0; i < SECP256K1_EC_PARSE_TEST_NINVALID; i++) {
        ec_pubkey_parse_pointtest(invalid[i], 0, 0);
    }
}

void random_sign(secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_scalar *key, const secp256k1_scalar *msg, int *recid) {
    secp256k1_scalar nonce;
    do {
        random_scalar_order_test(&nonce);
    } while(!secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, sigr, sigs, key, msg, &nonce, recid));
}

void test_ecdsa_sign_verify(void) {
    secp256k1_gej pubj;
    secp256k1_ge pub;
    secp256k1_scalar one;
    secp256k1_scalar msg, key;
    secp256k1_scalar sigr, sigs;
    int recid;
    int getrec;
    random_scalar_order_test(&msg);
    random_scalar_order_test(&key);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubj, &key);
    secp256k1_ge_set_gej(&pub, &pubj);
    getrec = secp256k1_rand32()&1;
    random_sign(&sigr, &sigs, &key, &msg, getrec?&recid:NULL);
    if (getrec) {
        CHECK(recid >= 0 && recid < 4);
    }
    CHECK(secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sigr, &sigs, &pub, &msg));
    secp256k1_scalar_set_int(&one, 1);
    secp256k1_scalar_add(&msg, &msg, &one);
    CHECK(!secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sigr, &sigs, &pub, &msg));
}

void run_ecdsa_sign_verify(void) {
    int i;
    for (i = 0; i < 10*count; i++) {
        test_ecdsa_sign_verify();
    }
}

/** Dummy nonce generation function that just uses a precomputed nonce, and fails if it is not accepted. Use only for testing. */
static int precomputed_nonce_function(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
    (void)msg32;
    (void)key32;
    (void)algo16;
    memcpy(nonce32, data, 32);
    return (counter == 0);
}

static int nonce_function_test_fail(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   /* Dummy nonce generator that has a fatal error on the first counter value. */
   if (counter == 0) {
       return 0;
   }
   return nonce_function_rfc6979(nonce32, msg32, key32, algo16, data, counter - 1);
}

static int nonce_function_test_retry(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   /* Dummy nonce generator that produces unacceptable nonces for the first several counter values. */
   if (counter < 3) {
       memset(nonce32, counter==0 ? 0 : 255, 32);
       if (counter == 2) {
           nonce32[31]--;
       }
       return 1;
   }
   if (counter < 5) {
       static const unsigned char order[] = {
           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
           0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
           0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
           0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
       };
       memcpy(nonce32, order, 32);
       if (counter == 4) {
           nonce32[31]++;
       }
       return 1;
   }
   /* Retry rate of 6979 is negligible esp. as we only call this in determinstic tests. */
   /* If someone does fine a case where it retries for secp256k1, we'd like to know. */
   if (counter > 5) {
       return 0;
   }
   return nonce_function_rfc6979(nonce32, msg32, key32, algo16, data, counter - 5);
}

int is_empty_signature(const secp256k1_ecdsa_signature *sig) {
    static const unsigned char res[sizeof(secp256k1_ecdsa_signature)] = {0};
    return memcmp(sig, res, sizeof(secp256k1_ecdsa_signature)) == 0;
}

void test_ecdsa_end_to_end(void) {
    unsigned char extra[32] = {0x00};
    unsigned char privkey[32];
    unsigned char message[32];
    unsigned char privkey2[32];
	int s = NUM_OF_SIGS;
    secp256k1_ecdsa_signature *signature = malloc(s*sizeof(secp256k1_ecdsa_signature));
    unsigned char sig[74];
    size_t siglen = 74;
    unsigned char pubkeyc[65];
    size_t pubkeyclen = 65;
    secp256k1_pubkey pubkey;
    unsigned char seckey[300];
    size_t seckeylen = 300;

    /* Generate a random key and message. */
    {
        secp256k1_scalar msg, key;
        random_scalar_order_test(&msg);
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(privkey, &key);
        secp256k1_scalar_get_b32(message, &msg);
    }

    /* Construct and verify corresponding public key. */
    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == 1);

    /* Verify exporting and importing public key. */
    CHECK(secp256k1_ec_pubkey_serialize(ctx, pubkeyc, &pubkeyclen, &pubkey, secp256k1_rand32() % 2) == 1);
    memset(&pubkey, 0, sizeof(pubkey));
    CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pubkeyc, pubkeyclen) == 1);

    /* Verify private key import and export. */
    CHECK(secp256k1_ec_privkey_export(ctx, seckey, &seckeylen, privkey, (secp256k1_rand32() % 2) == 1) ? SECP256K1_EC_COMPRESSED : 0);
    CHECK(secp256k1_ec_privkey_import(ctx, privkey2, seckey, seckeylen) == 1);
    CHECK(memcmp(privkey, privkey2, 32) == 0);

    /* Optionally tweak the keys using addition. */
    if (secp256k1_rand32() % 3 == 0) {
        int ret1;
        int ret2;
        unsigned char rnd[32];
        secp256k1_pubkey pubkey2;
        secp256k1_rand256_test(rnd);
        ret1 = secp256k1_ec_privkey_tweak_add(ctx, privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_add(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == 1);
        CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Optionally tweak the keys using multiplication. */
    if (secp256k1_rand32() % 3 == 0) {
        int ret1;
        int ret2;
        unsigned char rnd[32];
        secp256k1_pubkey pubkey2;
        secp256k1_rand256_test(rnd);
        ret1 = secp256k1_ec_privkey_tweak_mul(ctx, privkey, rnd);
        ret2 = secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, rnd);
        CHECK(ret1 == ret2);
        if (ret1 == 0) {
            return;
        }
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, privkey) == 1);
        CHECK(memcmp(&pubkey, &pubkey2, sizeof(pubkey)) == 0);
    }

    /* Sign. */
    
    /*CHECK(memcmp(&signature[0], &signature[4], sizeof(signature[0])) == 0);
    CHECK(memcmp(&signature[0], &signature[1], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[0], &signature[2], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[0], &signature[3], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[1], &signature[2], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[1], &signature[3], sizeof(signature[0])) != 0);
    CHECK(memcmp(&signature[2], &signature[3], sizeof(signature[0])) != 0);*/
    /* Verify. */
	
	int a;
	for(a=0;a<s;a++)
		secp256k1_ecdsa_sign(ctx, &signature[a], message, privkey, NULL, extra);
	
	char c;
	clock_t t; 
    t = clock();
	secp256k1_ecdsa_verify_arr(ctx, signature, message, &pubkey);
	
	t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
	printf("%d verify took %f seconds to execute \n",s, time_taken); 
	
	/*scanf("%c", &c);*/
	
	/*clock_t t; 
    t = clock();
	int a;
	for(a=0;a<1000000;a++)
	{
	CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
	CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[1], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[2], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[3], message, &pubkey) == 1);
	CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
	CHECK(secp256k1_ecdsa_verify(ctx, &signature[0], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[1], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[2], message, &pubkey) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature[3], message, &pubkey) == 1);
	}
	t = clock() - t; 
    double time_taken = ((double)t)/CLOCKS_PER_SEC;
	printf("10,000,000 verify took %f seconds to execute \n", time_taken); */

	
    /* Serialize/parse DER and verify again */
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature[0]) == 1);
    memset(&signature[0], 0, sizeof(signature[0]));
    CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature[0], sig, siglen) == 1);
    /*CHECK(secp256k1_ecdsa_verifyX(ctx, &signature[0], message, &pubkey) == 1);
     Serialize/destroy/parse DER and verify again. */
    siglen = 74;
    CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature[0]) == 1);
    sig[secp256k1_rand32() % siglen] += 1 + (secp256k1_rand32() % 255);
}

void test_random_pubkeys(void) {
    secp256k1_ge elem;
    secp256k1_ge elem2;
    unsigned char in[65];
    /* Generate some randomly sized pubkeys. */
    uint32_t r = secp256k1_rand32();
    size_t len = (r & 3) == 0 ? 65 : 33;
    r>>=2;
    if ((r & 3) == 0) {
        len = (r & 252) >> 3;
    }
    r>>=8;
    if (len == 65) {
      in[0] = (r & 2) ? 4 : ((r & 1)? 6 : 7);
    } else {
      in[0] = (r & 1) ? 2 : 3;
    }
    r>>=2;
    if ((r & 7) == 0) {
        in[0] = (r & 2040) >> 3;
    }
    r>>=11;
    if (len > 1) {
        secp256k1_rand256(&in[1]);
    }
    if (len > 33) {
        secp256k1_rand256(&in[33]);
    }
    if (secp256k1_eckey_pubkey_parse(&elem, in, len)) {
        unsigned char out[65];
        unsigned char firstb;
        int res;
        size_t size = len;
        firstb = in[0];
        /* If the pubkey can be parsed, it should round-trip... */
        CHECK(secp256k1_eckey_pubkey_serialize(&elem, out, &size, (len == 33) ? SECP256K1_EC_COMPRESSED : 0));
        CHECK(size == len);
        CHECK(memcmp(&in[1], &out[1], len-1) == 0);
        /* ... except for the type of hybrid inputs. */
        if ((in[0] != 6) && (in[0] != 7)) {
            CHECK(in[0] == out[0]);
        }
        size = 65;
        CHECK(secp256k1_eckey_pubkey_serialize(&elem, in, &size, 0));
        CHECK(size == 65);
        CHECK(secp256k1_eckey_pubkey_parse(&elem2, in, size));
        ge_equals_ge(&elem,&elem2);
        /* Check that the X9.62 hybrid type is checked. */
        in[0] = (r & 1) ? 6 : 7;
        res = secp256k1_eckey_pubkey_parse(&elem2, in, size);
        if (firstb == 2 || firstb == 3) {
            if (in[0] == firstb + 4) {
              CHECK(res);
            } else {
              CHECK(!res);
            }
        }
        if (res) {
            ge_equals_ge(&elem,&elem2);
            CHECK(secp256k1_eckey_pubkey_serialize(&elem, out, &size, 0));
            CHECK(memcmp(&in[1], &out[1], 64) == 0);
        }
    }
}

void run_random_pubkeys(void) {
    int i;
    for (i = 0; i < 10*count; i++) {
        test_random_pubkeys();
    }
}

void run_ecdsa_end_to_end(void) {
    int i;
	test_ecdsa_end_to_end();
    /*for (i = 0; i < 64*count; i++) {
        test_ecdsa_end_to_end();
    }*/
}

/* Tests several edge cases. */
void test_ecdsa_edge_cases(void) {
    int t;
    secp256k1_ecdsa_signature sig;

    /* Test the case where ECDSA recomputes a point that is infinity. */
    {
        secp256k1_gej keyj;
        secp256k1_ge key;
        secp256k1_scalar msg;
        secp256k1_scalar sr, ss;
        secp256k1_scalar_set_int(&ss, 1);
        secp256k1_scalar_negate(&ss, &ss);
        secp256k1_scalar_inverse(&ss, &ss);
        secp256k1_scalar_set_int(&sr, 1);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &keyj, &sr);
        secp256k1_ge_set_gej(&key, &keyj);
        msg = ss;
        CHECK(secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sr, &ss, &key, &msg) == 0);
    }

    /*Signature where s would be zero.*/
    {
        unsigned char signature[72];
        size_t siglen;
        const unsigned char nonce[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        static const unsigned char nonce2[32] = {
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
            0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
            0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40
        };
        const unsigned char key[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        };
        unsigned char msg[32] = {
            0x86, 0x41, 0x99, 0x81, 0x06, 0x23, 0x44, 0x53,
            0xaa, 0x5f, 0x9d, 0x6a, 0x31, 0x78, 0xf4, 0xf7,
            0xb8, 0x12, 0xe0, 0x0b, 0x81, 0x7a, 0x77, 0x62,
            0x65, 0xdf, 0xdd, 0x31, 0xb9, 0x3e, 0x29, 0xa9,
        };
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce) == 0);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce2) == 0);
        msg[31] = 0xaa;
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce) == 1);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, precomputed_nonce_function, nonce2) == 1);
        siglen = 72;
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, signature, &siglen, &sig) == 1);
        siglen = 10;
        CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, signature, &siglen, &sig) == 0);
    }

    /* Nonce function corner cases. */
    for (t = 0; t < 2; t++) {
        static const unsigned char zero[32] = {0x00};
        int i;
        unsigned char key[32];
        unsigned char msg[32];
        secp256k1_ecdsa_signature sig2;
        secp256k1_scalar sr[512], ss;
        const unsigned char *extra;
        extra = t == 0 ? NULL : zero;
        memset(msg, 0, 32);
        msg[31] = 1;
        /* High key results in signature failure. */
        memset(key, 0xFF, 32);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, NULL, extra) == 0);
        CHECK(is_empty_signature(&sig));
        /* Zero key results in signature failure. */
        memset(key, 0, 32);
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, NULL, extra) == 0);
        CHECK(is_empty_signature(&sig));
        /* Nonce function failure results in signature failure. */
        key[31] = 1;
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, nonce_function_test_fail, extra) == 0);
        CHECK(is_empty_signature(&sig));
        /* The retry loop successfully makes its way to the first good value. */
        CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, key, nonce_function_test_retry, extra) == 1);
        CHECK(!is_empty_signature(&sig));
        CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, nonce_function_rfc6979, extra) == 1);
        CHECK(!is_empty_signature(&sig2));
        CHECK(memcmp(&sig, &sig2, sizeof(sig)) == 0);
        /* The default nonce function is determinstic. */
        CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, NULL, extra) == 1);
        CHECK(!is_empty_signature(&sig2));
        CHECK(memcmp(&sig, &sig2, sizeof(sig)) == 0);
        /* The default nonce function changes output with different messages. */
        for(i = 0; i < 256; i++) {
            int j;
            msg[0] = i;
            CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, NULL, extra) == 1);
            CHECK(!is_empty_signature(&sig2));
            secp256k1_ecdsa_signature_load(ctx, &sr[i], &ss, &sig2);
            for (j = 0; j < i; j++) {
                CHECK(!secp256k1_scalar_eq(&sr[i], &sr[j]));
            }
        }
        msg[0] = 0;
        msg[31] = 2;
        /* The default nonce function changes output with different keys. */
        for(i = 256; i < 512; i++) {
            int j;
            key[0] = i - 256;
            CHECK(secp256k1_ecdsa_sign(ctx, &sig2, msg, key, NULL, extra) == 1);
            CHECK(!is_empty_signature(&sig2));
            secp256k1_ecdsa_signature_load(ctx, &sr[i], &ss, &sig2);
            for (j = 0; j < i; j++) {
                CHECK(!secp256k1_scalar_eq(&sr[i], &sr[j]));
            }
        }
        key[0] = 0;
    }

    /* Privkey export where pubkey is the point at infinity. */
    {
        unsigned char privkey[300];
        unsigned char seckey[32] = {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
        };
        size_t outlen = 300;
        CHECK(!secp256k1_ec_privkey_export(ctx, privkey, &outlen, seckey, 0));
        outlen = 300;
        CHECK(!secp256k1_ec_privkey_export(ctx, privkey, &outlen, seckey, SECP256K1_EC_COMPRESSED));
    }
}

void run_ecdsa_edge_cases(void) {
    test_ecdsa_edge_cases();
}

#ifdef ENABLE_OPENSSL_TESTS
EC_KEY *get_openssl_key(const secp256k1_scalar *key) {
    unsigned char privkey[300];
    size_t privkeylen;
    const unsigned char* pbegin = privkey;
    int compr = secp256k1_rand32() & 1;
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    CHECK(secp256k1_eckey_privkey_serialize(&ctx->ecmult_gen_ctx, privkey, &privkeylen, key, compr ? SECP256K1_EC_COMPRESSED : 0));
    CHECK(d2i_ECPrivateKey(&ec_key, &pbegin, privkeylen));
    CHECK(EC_KEY_check_key(ec_key));
    return ec_key;
}

void test_ecdsa_openssl(void) {
    secp256k1_gej qj;
    secp256k1_ge q;
    secp256k1_scalar sigr, sigs;
    secp256k1_scalar one;
    secp256k1_scalar msg2;
    secp256k1_scalar key, msg;
    EC_KEY *ec_key;
    unsigned int sigsize = 80;
    size_t secp_sigsize = 80;
    unsigned char message[32];
    unsigned char signature[80];
    secp256k1_rand256_test(message);
    secp256k1_scalar_set_b32(&msg, message, NULL);
    random_scalar_order_test(&key);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &qj, &key);
    secp256k1_ge_set_gej(&q, &qj);
    ec_key = get_openssl_key(&key);
    CHECK(ec_key != NULL);
    CHECK(ECDSA_sign(0, message, sizeof(message), signature, &sigsize, ec_key));
    CHECK(secp256k1_ecdsa_sig_parse(&sigr, &sigs, signature, sigsize));
    CHECK(secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sigr, &sigs, &q, &msg));
    secp256k1_scalar_set_int(&one, 1);
    secp256k1_scalar_add(&msg2, &msg, &one);
    CHECK(!secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &sigr, &sigs, &q, &msg2));

    random_sign(&sigr, &sigs, &key, &msg, NULL);
    CHECK(secp256k1_ecdsa_sig_serialize(signature, &secp_sigsize, &sigr, &sigs));
    CHECK(ECDSA_verify(0, message, sizeof(message), signature, secp_sigsize, ec_key) == 1);

    EC_KEY_free(ec_key);
}

void run_ecdsa_openssl(void) {
    int i;
    for (i = 0; i < 10*count; i++) {
        test_ecdsa_openssl();
    }
}
#endif

#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/tests_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORR
# include "modules/schnorr/tests_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/tests_impl.h"
#endif

int main(int argc, char **argv) {
    unsigned char seed16[16] = {0};
    unsigned char run32[32] = {0};
    /* find iteration count */
    if (argc > 1) {
        count = strtol(argv[1], NULL, 0);
    }

    /* find random seed */
    if (argc > 2) {
        int pos = 0;
        const char* ch = argv[2];
        while (pos < 16 && ch[0] != 0 && ch[1] != 0) {
            unsigned short sh;
            if (sscanf(ch, "%2hx", &sh)) {
                seed16[pos] = sh;
            } else {
                break;
            }
            ch += 2;
            pos++;
        }
    } else {
        FILE *frand = fopen("/dev/urandom", "r");
        if ((frand == NULL) || !fread(&seed16, sizeof(seed16), 1, frand)) {
            uint64_t t = time(NULL) * (uint64_t)1337;
            seed16[0] ^= t;
            seed16[1] ^= t >> 8;
            seed16[2] ^= t >> 16;
            seed16[3] ^= t >> 24;
            seed16[4] ^= t >> 32;
            seed16[5] ^= t >> 40;
            seed16[6] ^= t >> 48;
            seed16[7] ^= t >> 56;
        }
        fclose(frand);
    }
    secp256k1_rand_seed(seed16);

    printf("test count = %i\n", count);
    printf("random seed = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", seed16[0], seed16[1], seed16[2], seed16[3], seed16[4], seed16[5], seed16[6], seed16[7], seed16[8], seed16[9], seed16[10], seed16[11], seed16[12], seed16[13], seed16[14], seed16[15]);
    /* initialize */
    run_context_tests();
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    if (secp256k1_rand32() & 1) {
        secp256k1_rand256(run32);
        CHECK(secp256k1_context_randomize(ctx, (secp256k1_rand32() & 1) ? run32 : NULL));
    }
    run_sha256_tests();
    run_hmac_sha256_tests();
    run_rfc6979_hmac_sha256_tests();

#ifndef USE_NUM_NONE
    /* num tests */
    run_num_smalltests();
#endif

    /* scalar tests */
    run_scalar_tests();

    /* field tests */
    /*run_field_inv();
    run_field_inv_var();
    run_field_inv_all_var();
    run_field_misc();
    run_field_convert();
    run_sqr();
    run_sqrt();*/

    /* group tests */
    /*run_ge();*/

    /* ecmult tests */
    /*run_wnaf();
    run_point_times_order();
    run_ecmult_chain();
    run_ecmult_constants();
    run_ecmult_gen_blind();
    run_ecmult_const_tests();
    run_ec_combine();*/

    /* endomorphism tests */
#ifdef USE_ENDOMORPHISM
    /*run_endomorphism_tests();*/
#endif

    /* EC point parser test*/
    /*run_ec_pubkey_parse_test();*/

#ifdef ENABLE_MODULE_ECDH
    /* ecdh tests */
    /*run_ecdh_tests();*/
#endif

    /* ecdsa tests */
    run_random_pubkeys();
    run_ecdsa_sign_verify();
    run_ecdsa_end_to_end();
    run_ecdsa_edge_cases();
#ifdef ENABLE_OPENSSL_TESTS
    run_ecdsa_openssl();
#endif

#ifdef ENABLE_MODULE_SCHNORR
    /* Schnorr tsts */
    run_schnorr_tests();
#endif

#ifdef ENABLE_MODULE_RECOVERY
    /* ECDSA pubkey recovery tests */
    run_recovery_tests();
#endif

    secp256k1_rand256(run32);
    printf("random run = %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", run32[0], run32[1], run32[2], run32[3], run32[4], run32[5], run32[6], run32[7], run32[8], run32[9], run32[10], run32[11], run32[12], run32[13], run32[14], run32[15]);

    /* shutdown */
    secp256k1_context_destroy(ctx);

    printf("no problems found\n");
    return 0;
}
