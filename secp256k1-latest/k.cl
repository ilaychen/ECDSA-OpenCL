 /*Copyright Ilay Chen and Yakir Fenton*/
typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;

#ifdef DETERMINISTIC
#define CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE("test condition failed"); \
    } \
} while(0)
#else
#define CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        TEST_FAILURE("test condition failed: " #cond); \
    } \
} while(0)
#endif

/* Like assert(), but when VERIFY is defined, and side-effect safe. */
#ifdef VERIFY
#define VERIFY_CHECK CHECK
#define VERIFY_SETUP(stmt) do { stmt; } while(0)
#else
#define VERIFY_CHECK(cond) do { (void)(cond); } while(0)
#define VERIFY_SETUP(stmt)
#endif

# define SECP256K1_RESTRICT
#  define WINDOW_A 5 
#define ECMULT_WINDOW_SIZE 15 
#  define WINDOW_G ECMULT_WINDOW_SIZE
#define ECMULT_TABLE_SIZE(w) (1 << ((w)-2))
#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { \
    (d0) | (((ulong)(d1) & 0xFFFFFUL) << 32), \
    ((ulong)(d1) >> 20) | (((ulong)(d2)) << 12) | (((ulong)(d3) & 0xFFUL) << 44), \
    ((ulong)(d3) >> 8) | (((ulong)(d4) & 0xFFFFFFFUL) << 24), \
    ((ulong)(d4) >> 28) | (((ulong)(d5)) << 4) | (((ulong)(d6) & 0xFFFFUL) << 36), \
    ((ulong)(d6) >> 16) | (((ulong)(d7)) << 16) \
}
#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)), 1, 1}


#define SECP256K1_N_0 ((ulong)0xBfD25E8CD0364141UL)
#define SECP256K1_N_1 ((ulong)0xBAAEDCE6Af48A03BUL)
#define SECP256K1_N_2 ((ulong)0xfffffffffffffffEUL)
#define SECP256K1_N_3 ((ulong)0xffffffffffffffffUL)

/* Limbs of 2^256 minus the secp256k1 order. */
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)

/* Limbs of half the secp256k1 order. */
#define SECP256K1_N_H_0 ((ulong)0xDFE92F46681B20A0UL)
#define SECP256K1_N_H_1 ((ulong)0x5D576E7357A4501DUL)
#define SECP256K1_N_H_2 ((ulong)0xffffffffffffffffUL)
#define SECP256K1_N_H_3 ((ulong)0x7fffffffffffffffUL)

#define muladd(a,b) { \
    ulong tl, th; \
    { \
        unsigned long long t = a * (unsigned long long)b; \
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
    ulong tl, th; \
    { \
        unsigned long long t = a * (unsigned long long)b; \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* never overflows by contract (verified in the next line) */ \
}

/** Add 2*a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd2(a,b) { \
    ulong tl, th, th2, tl2; \
    { \
		unsigned long long t = a * (unsigned long long)b; \
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

typedef struct {
    ulong d[4];
} secp256k1_scalarX;

typedef struct {
    ulong n[5];
/*#ifdef VERIFY*/
    int magnitude;
    int normalized;
/*#endif*/
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
    ulong n[4];
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


__constant secp256k1_feX secp256k1_ecdsa_const_p_minus_orderX = SECP256K1_FE_CONST(
    0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xfffffffEUL,
    0xBAAEDCE6UL, 0xAf48A03BUL, 0xBfD25E8CUL, 0xD0364141UL
);

__constant secp256k1_feX secp256k1_ecdsa_const_order_as_feX = SECP256K1_FE_CONST(
    0xffffffffUL, 0xffffffffUL, 0xffffffffUL, 0xfffffffEUL,
    0xBAAEDCE6UL, 0xAf48A03BUL, 0xBfD25E8CUL, 0xD0364141UL
);

static void secp256k1_fe_verifyX(const secp256k1_feX *a) {
    const uint *d = a->n;
    int m = a->normalized ? 1 : 2 * a->magnitude, r = 1;
    r &= (d[0] <= 0x3ffffffUL * m);
    r &= (d[1] <= 0x3ffffffUL * m);
    r &= (d[2] <= 0x3ffffffUL * m);
    r &= (d[3] <= 0x3ffffffUL * m);
    r &= (d[4] <= 0x3ffffffUL * m);
    r &= (d[5] <= 0x3ffffffUL * m);
    r &= (d[6] <= 0x3ffffffUL * m);
    r &= (d[7] <= 0x3ffffffUL * m);
    r &= (d[8] <= 0x3ffffffUL * m);
    r &= (d[9] <= 0x03fffffUL * m);
    r &= (a->magnitude >= 0);
    r &= (a->magnitude <= 32);
    if (a->normalized) {
        r &= (a->magnitude <= 1);
        if (r && (d[9] == 0x03fffffUL)) {
            uint mid = d[8] & d[7] & d[6] & d[5] & d[4] & d[3] & d[2];
            if (mid == 0x3ffffffUL) {
                r &= ((d[1] + 0x40UL + ((d[0] + 0x3D1UL) >> 26)) <= 0x3ffffffUL);
            }
        }
    }
}

int secp256k1_scalar_check_overflowX(secp256k1_scalarX *a) {
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

int secp256k1_scalar_reduceX(secp256k1_scalarX *r, unsigned int overflow) {
    unsigned long long t;
    t = (unsigned long long)r->d[0] + overflow * SECP256K1_N_C_0;
    r->d[0] = t & 0xffffffffffffffffUL; t >>= 64;
    t += (unsigned long long)r->d[1] + overflow * SECP256K1_N_C_1;
    r->d[1] = t & 0xffffffffffffffffUL; t >>= 64;
    t += (unsigned long long)r->d[2] + overflow * SECP256K1_N_C_2;
    r->d[2] = t & 0xffffffffffffffffUL; t >>= 64;
    t += (unsigned long)r->d[3];
    r->d[3] = t & 0xffffffffffffffffUL;
    return overflow;
}

static void secp256k1_scalar_set_b32X(secp256k1_scalarX *r, global const unsigned char *b32, int *overflow) {
    int over;
    r->d[0] = (ulong)b32[31] | (ulong)b32[30] << 8 | (ulong)b32[29] << 16 | (ulong)b32[28] << 24 | (ulong)b32[27] << 32 | (ulong)b32[26] << 40 | (ulong)b32[25] << 48 | (ulong)b32[24] << 56;
    r->d[1] = (ulong)b32[23] | (ulong)b32[22] << 8 | (ulong)b32[21] << 16 | (ulong)b32[20] << 24 | (ulong)b32[19] << 32 | (ulong)b32[18] << 40 | (ulong)b32[17] << 48 | (ulong)b32[16] << 56;
    r->d[2] = (ulong)b32[15] | (ulong)b32[14] << 8 | (ulong)b32[13] << 16 | (ulong)b32[12] << 24 | (ulong)b32[11] << 32 | (ulong)b32[10] << 40 | (ulong)b32[9] << 48 | (ulong)b32[8] << 56;
    r->d[3] = (ulong)b32[7] | (ulong)b32[6] << 8 | (ulong)b32[5] << 16 | (ulong)b32[4] << 24 | (ulong)b32[3] << 32 | (ulong)b32[2] << 40 | (ulong)b32[1] << 48 | (ulong)b32[0] << 56;
    over = secp256k1_scalar_reduceX(r, secp256k1_scalar_check_overflowX(r));
    if (overflow) {
        *overflow = over;
    }
}

void memcpyX(void *dest, global const void *src, size_t len)
{
  char *d = dest;
  global const char *s = src;
  while (len--)
    *d++ = *s++;
}

static void secp256k1_ecdsa_signature_loadX(global const secp256k1_contextX* ctx, secp256k1_scalarX* r, secp256k1_scalarX* s, global secp256k1_ecdsa_signatureX* sig) {
    (void)ctx;
    if (sizeof(secp256k1_scalarX) == 32) {
        memcpyX(r, &sig->data[0], 32);
        memcpyX(s, &sig->data[32], 32);
    } else {
        secp256k1_scalar_set_b32X(r, &sig->data[0], NULL);
        secp256k1_scalar_set_b32X(s, &sig->data[32], NULL);
    }
}

void secp256k1_fe_from_storageX(secp256k1_feX *r, __global secp256k1_fe_storageX *a) {
    r->n[0] = a->n[0] & 0xfffffffffffffUL;
    r->n[1] = a->n[0] >> 52 | ((a->n[1] << 12) & 0xfffffffffffffUL);
    r->n[2] = a->n[1] >> 40 | ((a->n[2] << 24) & 0xfffffffffffffUL);
    r->n[3] = a->n[2] >> 28 | ((a->n[3] << 36) & 0xfffffffffffffUL);
    r->n[4] = a->n[3] >> 16;
    r->magnitude = 1;
    r->normalized = 1;
}

void secp256k1_fe_from_storageX_m(secp256k1_feX *r, secp256k1_fe_storageX a) {
    r->n[0] = a.n[0] & 0xfffffffffffffUL;
    r->n[1] = a.n[0] >> 52 | ((a.n[1] << 12) & 0xfffffffffffffUL);
    r->n[2] = a.n[1] >> 40 | ((a.n[2] << 24) & 0xfffffffffffffUL);
    r->n[3] = a.n[2] >> 28 | ((a.n[3] << 36) & 0xfffffffffffffUL);
    r->n[4] = a.n[3] >> 16;
    r->magnitude = 1;
    r->normalized = 1;
}

static void secp256k1_ge_from_storageX_m(secp256k1_geX *r, secp256k1_ge_storageX a) {
	printf("ge G %ul %ul \n", a.x.n[0], a.y.n[0]);
    secp256k1_fe_from_storageX_m(&r->x, a.x);
    secp256k1_fe_from_storageX_m(&r->y, a.y);
	/*printf("C %ul %ul %ul %ul \n", r->x.n[0], r->y.n[0], a->x.n[0], a->y.n[0]);*/
    r->infinity = 0;
}

void secp256k1_fe_from_storageX_s(secp256k1_feX *r, const secp256k1_fe_storageX *a) {
    r->n[0] = a->n[0] & 0xfffffffffffffUL;
    r->n[1] = a->n[0] >> 52 | ((a->n[1] << 12) & 0xfffffffffffffUL);
    r->n[2] = a->n[1] >> 40 | ((a->n[2] << 24) & 0xfffffffffffffUL);
    r->n[3] = a->n[2] >> 28 | ((a->n[3] << 36) & 0xfffffffffffffUL);
    r->n[4] = a->n[3] >> 16;
    r->magnitude = 1;
    r->normalized = 1;
}

static void secp256k1_ge_from_storageX(secp256k1_geX *r, __global secp256k1_ge_storageX *a) {
	//printf("ge C %ul %ul \n", a->x.n[0], a->y.n[0]);
    secp256k1_fe_from_storageX(&r->x, &a->x);
    secp256k1_fe_from_storageX(&r->y, &a->y);
	//printf("G %ul %ul %ul %ul \n", r->x.n[0], r->y.n[0], a->x.n[0], a->y.n[0]);
    r->infinity = 0;
}

static void secp256k1_ge_from_storageX_s(secp256k1_geX *r, const secp256k1_ge_storageX *a) {
    secp256k1_fe_from_storageX_s(&r->x, &a->x);
    secp256k1_fe_from_storageX_s(&r->y, &a->y);
    r->infinity = 0;
}

static void secp256k1_ge_set_xyX(secp256k1_geX *r, const secp256k1_feX *x, const secp256k1_feX *y) {
    r->infinity = 0;
    r->x = *x;
    r->y = *y;
}

static int secp256k1_fe_set_b32X(secp256k1_feX *r, global const unsigned char *a) {
	int i;
    r->n[0] = r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
    for (i=0; i<32; i++) {
        int j;
        for (j=0; j<2; j++) {
            int limb = (8*i+4*j)/52;
            int shift = (8*i+4*j)%52;
            r->n[limb] |= (ulong)((a[31-i] >> (4*j)) & 0xf) << shift;
        }
    }
    if (r->n[4] == 0x0ffffffffffffUL && (r->n[3] & r->n[2] & r->n[1]) == 0xfffffffffffffUL && r->n[0] >= 0xffffEfffffC2fUL) {
        return 0;
    }
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verifyX(r);
    return 1;
}

static int secp256k1_fe_set_b32XX(secp256k1_feX *r, const unsigned char *a) {
	int i;
    r->n[0] = r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
    for (i=0; i<32; i++) {
        int j;
        for (j=0; j<2; j++) {
            int limb = (8*i+4*j)/52;
            int shift = (8*i+4*j)%52;
            r->n[limb] |= (ulong)((a[31-i] >> (4*j)) & 0xF) << shift;
        }
    }
    if (r->n[4] == 0x0ffffffffffffUL && (r->n[3] & r->n[2] & r->n[1]) == 0xfffffffffffffUL && r->n[0] >= 0xffffEfffffC2fUL) {
        return 0;
    }
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verifyX(r);
    return 1;
}

static int secp256k1_pubkey_loadX(global const secp256k1_contextX* ctx, secp256k1_geX* ge, global const secp256k1_pubkeyX* pubkey) {
    if (sizeof(secp256k1_ge_storageX) == 64) {
        /* When the secp256k1_ge_storageX type is exactly 64 byte, use its
         * representation inside secp256k1_pubkeyX, as conversion is very fast.
         * Note that secp256k1_pubkey_save must use the same representation. */
        secp256k1_ge_storageX s;
        memcpyX(&s, &pubkey->data[0], 64);
        secp256k1_ge_from_storageX_s(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        secp256k1_feX x, y;
        secp256k1_fe_set_b32X(&x, pubkey->data);
        secp256k1_fe_set_b32X(&y, pubkey->data + 32);
        secp256k1_ge_set_xyX(ge, &x, &y);
    }
    return 1;
}

int secp256k1_scalar_is_zeroX(const secp256k1_scalarX *a) {
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

void secp256k1_scalar_sqr_512X(ulong l[8], const secp256k1_scalarX *a) {
    /* 160 bit accumulator. */
    ulong c0 = 0, c1 = 0;
    uint c2 = 0;

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

static void secp256k1_scalar_reduce_512X(secp256k1_scalarX *r, const ulong *l) {
    uint128_t c;
    ulong c0, c1, c2;
    ulong n0 = l[4], n1 = l[5], n2 = l[6], n3 = l[7];
    ulong m0, m1, m2, m3, m4, m5;
    uint m6;
    ulong p0, p1, p2, p3;
    uint p4;

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
    r->d[0] = c & 0xffffffffffffffffUL; c >>= 64;
    c += p1 + (uint128_t)SECP256K1_N_C_1 * p4;
    r->d[1] = c & 0xffffffffffffffffUL; c >>= 64;
    c += p2 + (uint128_t)p4;
    r->d[2] = c & 0xffffffffffffffffUL; c >>= 64;
    c += p3;
    r->d[3] = c & 0xffffffffffffffffUL; c >>= 64;

    /* Final reduction of r. */
    secp256k1_scalar_reduceX(r, c + secp256k1_scalar_check_overflowX(r));
}

void secp256k1_scalar_sqrX(secp256k1_scalarX *r, const secp256k1_scalarX *a) {
    ulong l[8];
    secp256k1_scalar_sqr_512X(l, a);
    secp256k1_scalar_reduce_512X(r, l);
}


static void secp256k1_scalar_mul_512X(ulong l[8], const secp256k1_scalarX *a, const secp256k1_scalarX *b) {
    ulong c0 = 0, c1 = 0;
    uint c2 = 0;

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
    ulong l[8];
    secp256k1_scalar_mul_512X(l, a, b);
    secp256k1_scalar_reduce_512X(r, l);
}

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

void secp256k1_fe_set_intX(secp256k1_feX *r, int a) {
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verifyX(r);
}

static void secp256k1_gej_set_geX(secp256k1_gejX *r, const secp256k1_geX *a) {
	r->x = a->x;
	r->y = a->y;
	r->infinity = a->infinity;
	secp256k1_fe_set_intX(&r->z, 1);
}

static int secp256k1_gej_is_infinityX(const secp256k1_gejX *a) {
    return a->infinity;
}

unsigned int secp256k1_scalar_get_bitsX(const secp256k1_scalarX *a, unsigned int offset, unsigned int count) {
    return (a->d[offset >> 6] >> (offset & 0x3F)) & ((((ulong)1) << count) - 1);
}

static void secp256k1_scalar_negateX(secp256k1_scalarX *r, const secp256k1_scalarX *a) {
    ulong nonzero = 0xffffffffffffffffUL * (secp256k1_scalar_is_zeroX(a) == 0);
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
        return ((a->d[offset >> 6] >> (offset & 0x3F)) | (a->d[(offset >> 6) + 1] << (64 - (offset & 0x3F)))) & ((((ulong)1) << count) - 1);
    }
}

void secp256k1_fe_mul_innerX(ulong *r, const ulong *a, const ulong * SECP256K1_RESTRICT b) {
    uint128_t c, d;
    ulong t3, t4, tx, u0;
    ulong a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    const ulong M = 0xfffffffffffffUL, R = 0x1000003D10UL;


    d  = (uint128_t)a0 * b[3]
       + (uint128_t)a1 * b[2]
       + (uint128_t)a2 * b[1]
       + (uint128_t)a3 * b[0];
    c  = (uint128_t)a4 * b[4];
    d += (c & M) * R; c >>= 52;
    t3 = d & M; d >>= 52;

    d += (uint128_t)a0 * b[4]
       + (uint128_t)a1 * b[3]
       + (uint128_t)a2 * b[2]
       + (uint128_t)a3 * b[1]
       + (uint128_t)a4 * b[0];
    d += c * R;
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
	//printf("M   %lu\n", M);
	//printf("M&c %lu\n", M&c);
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


void secp256k1_fe_mul_innerX_z(ulong *r, ulong *a, const ulong * SECP256K1_RESTRICT b) {

    uint128_t c, d;
    ulong t3, t4, tx, u0;
    ulong a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
	ulong M = 0xfffffffffffffUL, R = 0x1000003D10UL;


    d  = (uint128_t)a0 * b[3]
       + (uint128_t)a1 * b[2]
       + (uint128_t)a2 * b[1]
       + (uint128_t)a3 * b[0];
    c  = (uint128_t)a4 * b[4];
    d += (c & M) * R; c >>= 52;
    t3 = d & M; d >>= 52;

    d += (uint128_t)a0 * b[4]
       + (uint128_t)a1 * b[3]
       + (uint128_t)a2 * b[2]
       + (uint128_t)a3 * b[1]
       + (uint128_t)a4 * b[0];
    d += c * R;
    t4 = d & M; d >>= 52;
    tx = (t4 >> 48); t4 &= (M >> 4);

    c  = (uint128_t)a0 * b[0];
    d += (uint128_t)a1 * b[4]
       + (uint128_t)a2 * b[3]
       + (uint128_t)a3 * b[2]
       + (uint128_t)a4 * b[1];
    u0 = d & M; d >>= 52;
    u0 = (u0 << 4) | tx;
    c += (uint128_t)u0 * (R >> 4);
	//printf("\n??? %lu",c & M);
    r[0] = c & M; 
	c >>= 52;
    
    c += (uint128_t)a0 * b[1]
       + (uint128_t)a1 * b[0];
    d += (uint128_t)a2 * b[4]
       + (uint128_t)a3 * b[3]
       + (uint128_t)a4 * b[2];
    c += (d & M) * R; d >>= 52;
    r[1] = c & M; c >>= 52;

    c += (uint128_t)a0 * b[2]
       + (uint128_t)a1 * b[1]
       + (uint128_t)a2 * b[0];
    d += (uint128_t)a3 * b[4]
       + (uint128_t)a4 * b[3];
    c += (d & M) * R; d >>= 52;

    r[2] = c & M; c >>= 52;
    c   += d * R + t3;
    r[3] = c & M; c >>= 52;
    c   += t4;
    r[4] = c;
}


ulong secp256k1_fe_mul_innerXXX(ulong *r, const ulong *a, const ulong * SECP256K1_RESTRICT b) {
    uint128_t c, d;
    ulong t3, t4, tx, u0;
    ulong a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    const ulong M = 0xfffffffffffffUL, R = 0x1000003D10UL;


    d  = (uint128_t)a0 * b[3]
       + (uint128_t)a1 * b[2]
       + (uint128_t)a2 * b[1]
       + (uint128_t)a3 * b[0];
    c  = (uint128_t)a4 * b[4];
    d += (c & M) * R; c >>= 52;
    t3 = d & M; d >>= 52;

    d += (uint128_t)a0 * b[4]
       + (uint128_t)a1 * b[3]
       + (uint128_t)a2 * b[2]
       + (uint128_t)a3 * b[1]
       + (uint128_t)a4 * b[0];
    d += c * R;
    t4 = d & M; d >>= 52;
    tx = (t4 >> 48); t4 &= (M >> 4);

    c  = (uint128_t)a0 * b[0];
    d += (uint128_t)a1 * b[4]
       + (uint128_t)a2 * b[3]
       + (uint128_t)a3 * b[2]
       + (uint128_t)a4 * b[1];
    u0 = d & M; d >>= 52;
    u0 = (u0 << 4) | tx;
    c += (uint128_t)u0 * (R >> 4);
	r[0] = c & M; 
	c >>= 52;
/*
    c += (uint128_t)a0 * b[1]
       + (uint128_t)a1 * b[0];
    d += (uint128_t)a2 * b[4]
       + (uint128_t)a3 * b[3]
       + (uint128_t)a4 * b[2];
    c += (d & M) * R; d >>= 52;
    r[1] = c & M; c >>= 52;

    c += (uint128_t)a0 * b[2]
       + (uint128_t)a1 * b[1]
       + (uint128_t)a2 * b[0];
    d += (uint128_t)a3 * b[4]
       + (uint128_t)a4 * b[3];
    c += (d & M) * R; d >>= 52;

    r[2] = c & M; c >>= 52;
    c   += d * R + t3;
    r[3] = c & M; c >>= 52;
    c   += t4;
    r[4] = c;*/
}

void memsetX(void *dest, int val, size_t len)
{
  unsigned char *ptr = dest;
  while (len-- > 0)
    *ptr++ = val;
}


static void secp256k1_fe_mulX(secp256k1_feX *r, const secp256k1_feX *a, const secp256k1_feX * SECP256K1_RESTRICT b) {

    secp256k1_fe_verifyX(a);
    secp256k1_fe_verifyX(b);
    secp256k1_fe_mul_innerX(r->n, a->n, b->n);
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}

static void secp256k1_fe_mulX_z(secp256k1_feX *r,  secp256k1_feX *a, const secp256k1_feX * SECP256K1_RESTRICT b) {

    secp256k1_fe_verifyX(a);
    secp256k1_fe_verifyX(b);
    secp256k1_fe_mul_innerX(r->n, a->n, b->n);
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}



static void secp256k1_fe_mulXXX(secp256k1_feX *r, const secp256k1_feX *a, const secp256k1_feX * SECP256K1_RESTRICT b) {

    secp256k1_fe_verifyX(a);
    secp256k1_fe_verifyX(b);
	ulong arr[5];
    secp256k1_fe_mul_innerXXX(arr, a->n, b->n);
	r->n[0] = arr; /*TODO this is not correct*/
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}

static void secp256k1_fe_mulXX(secp256k1_feX *r, secp256k1_feX *a, secp256k1_feX * SECP256K1_RESTRICT b) {

    /*secp256k1_fe_verifyX(a);
    secp256k1_fe_verifyX(b); TODO*/
    /*secp256k1_fe_mul_innerX(r->n, a->n, b->n);*/
    /*r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verifyX(r); TODO*/
}



static int secp256k1_ecmult_wnafX(int *wnaf, int len, const secp256k1_scalarX *a, int w) {
    secp256k1_scalarX s;
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;

    memsetX(wnaf, 0, len * sizeof(wnaf[0]));

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

static void secp256k1_fe_normalize_weakX(secp256k1_feX *r) {
    ulong t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    ulong x = t4 >> 48; t4 &= 0x0ffffffffffffUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1UL;
    t1 += (t0 >> 52); t0 &= 0xfffffffffffffUL;
    t2 += (t1 >> 52); t1 &= 0xfffffffffffffUL;
    t3 += (t2 >> 52); t2 &= 0xfffffffffffffUL;
    t4 += (t3 >> 52); t3 &= 0xfffffffffffffUL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    secp256k1_fe_verifyX(r);
#endif
}

void secp256k1_fe_sqr_innerX(ulong *r, const ulong *a) {
    uint128_t c, d;
    ulong a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    long t3, t4, tx, u0;
    const ulong M = 0xfffffffffffffUL, R = 0x1000003D10UL;

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

void secp256k1_fe_negateX(secp256k1_feX *r, const secp256k1_feX *a, int m) {
    secp256k1_fe_verifyX(a);
    r->n[0] = 0xffffEfffffC2fUL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0xfffffffffffffUL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0xfffffffffffffUL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0xfffffffffffffUL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x0ffffffffffffUL * 2 * (m + 1) - a->n[4];
    r->magnitude = m + 1;
    r->normalized = 0;
    secp256k1_fe_verifyX(r);
}


static void secp256k1_fe_sqrX(secp256k1_feX *r, const secp256k1_feX *a) {
    secp256k1_fe_verifyX(a);
    secp256k1_fe_sqr_innerX(r->n, a->n);
    r->magnitude = 1;
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

void secp256k1_fe_addXX(secp256k1_feX *r, __constant secp256k1_feX *a) {
    /*secp256k1_fe_verifyX(a);*/
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
    r->magnitude += a->magnitude;
    r->normalized = 0;
    /*secp256k1_fe_verifyX(r);*/
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
    ulong t0, t1, t2, t3, t4;
    ulong z0, z1;
    ulong x;

    t0 = r->n[0];
    t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    x = t4 >> 48;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1UL;

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0xfffffffffffffUL;
    z1 = z0 ^ 0x1000003D0UL;

    /* Fast return path should catch the majority of cases */
    if ((z0 != 0UL) & (z1 != 0xfffffffffffffUL)) {
        return 0;
    }

    t1 = r->n[1];
    t2 = r->n[2];
    t3 = r->n[3];

    t4 &= 0x0ffffffffffffUL;

    t1 += (t0 >> 52);
    t2 += (t1 >> 52); t1 &= 0xfffffffffffffUL; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xfffffffffffffUL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xfffffffffffffUL; z0 |= t3; z1 &= t3;
                                                z0 |= t4; z1 &= t4 ^ 0xf000000000000UL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */

    return (z0 == 0) | (z1 == 0xfffffffffffffUL);
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
    ulong t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    ulong m;
    ulong x = t4 >> 48; t4 &= 0x0ffffffffffffUL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1UL;
    t1 += (t0 >> 52); t0 &= 0xfffffffffffffUL;
    t2 += (t1 >> 52); t1 &= 0xfffffffffffffUL; m = t1;
    t3 += (t2 >> 52); t2 &= 0xfffffffffffffUL; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xfffffffffffffUL; m &= t3;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0ffffffffffffUL) & (m == 0xfffffffffffffUL)
        & (t0 >= 0xffffEfffffC2fUL));

    if (x) {
        t0 += 0x1000003D1UL;
        t1 += (t0 >> 52); t0 &= 0xfffffffffffffUL;
        t2 += (t1 >> 52); t1 &= 0xfffffffffffffUL;
        t3 += (t2 >> 52); t2 &= 0xfffffffffffffUL;
        t4 += (t3 >> 52); t3 &= 0xfffffffffffffUL;

        /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */

        /* Mask off the possible multiple of 2^256 from the final reduction */
        t4 &= 0x0ffffffffffffUL;
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

void secp256k1_fe_clearX(secp256k1_feX *a) {
    int i;
    a->magnitude = 0;
    a->normalized = 1;
    for (i=0; i<5; i++) {
        a->n[i] = 0;
    }
}

static void secp256k1_gej_set_infinityX(secp256k1_gejX *r) {
    r->infinity = 1;
    secp256k1_fe_clearX(&r->x);
    secp256k1_fe_clearX(&r->y);
    secp256k1_fe_clearX(&r->z);
}

#define ECMULT_TABLE_GET_GE(r,pre,n,w) do { \
    if ((n) > 0) { \
        *(r) = (pre)[((n)-1)/2]; \
    } else { \
        *(r) = (pre)[(-(n)-1)/2]; \
        secp256k1_fe_negateX(&((r)->y), &((r)->y), 1); \
    } \
} while(0)

#define ECMULT_TABLE_GET_GE_STORAGE(r,pre,n,w) do { \
    if ((n) > 0) { \
		printf("+ A C y %ul \n", (pre)[((n)-1)/2].x.n[0]); \
        secp256k1_ge_from_storageX_m((r), pre[((n)-1)/2]); \
    } else { \
		printf("- A C y %ul \n", (pre)[(-(n)-1)/2].x.n[0]); \
		secp256k1_ge_from_storageX_m((r), pre[(-(n)-1)/2]); \
        secp256k1_fe_negateX(&((r)->y), &((r)->y), 1); \
    } \
} while(0)

void ulongsetX(ulong *dest, ulong *src, int len)
{
  while (len-- > 0)
    dest[len] = src[len];
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



void secp256k1_ecmult_strauss_wnafX(global const secp256k1_ge_storageX *ctx, const struct secp256k1_strauss_stateX *state, secp256k1_gejX *r, int num, const secp256k1_gejX *a, const secp256k1_scalarX *na, const secp256k1_scalarX *ng) 
{
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
			//printf("\nG G %ul", ctx[0].x.n[0]);
			/*printf("\ni %d ", i);
			printf("A G x %ul ", ctx[i].x.n[0]);
			printf("A G y %ul  ", ctx[i].y.n[0]);*/
			ECMULT_TABLE_GET_GE_STORAGE(&tmpa, ctx, n, WINDOW_G);
			printf("\nA G x %ul ", tmpa.x.n[0]);
			printf("A G y %ul \n", tmpa.y.n[0]);
            secp256k1_gej_add_zinv_varX(r, r, &tmpa, &Z);
			
        }
    }
    if (!r->infinity) {
        secp256k1_fe_mulX(&r->z, &r->z, &Z);
    }
}

static void secp256k1_ecmultX(global const secp256k1_ge_storageX *ctx, secp256k1_gejX *r, const secp256k1_gejX *a, const secp256k1_scalarX *na, const secp256k1_scalarX *ng) {
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

static void secp256k1_scalar_get_b32X(unsigned char *bin, const secp256k1_scalarX* a) {
    bin[0] = a->d[3] >> 56; bin[1] = a->d[3] >> 48; bin[2] = a->d[3] >> 40; bin[3] = a->d[3] >> 32; bin[4] = a->d[3] >> 24; bin[5] = a->d[3] >> 16; bin[6] = a->d[3] >> 8; bin[7] = a->d[3];
    bin[8] = a->d[2] >> 56; bin[9] = a->d[2] >> 48; bin[10] = a->d[2] >> 40; bin[11] = a->d[2] >> 32; bin[12] = a->d[2] >> 24; bin[13] = a->d[2] >> 16; bin[14] = a->d[2] >> 8; bin[15] = a->d[2];
    bin[16] = a->d[1] >> 56; bin[17] = a->d[1] >> 48; bin[18] = a->d[1] >> 40; bin[19] = a->d[1] >> 32; bin[20] = a->d[1] >> 24; bin[21] = a->d[1] >> 16; bin[22] = a->d[1] >> 8; bin[23] = a->d[1];
    bin[24] = a->d[0] >> 56; bin[25] = a->d[0] >> 48; bin[26] = a->d[0] >> 40; bin[27] = a->d[0] >> 32; bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
}

int secp256k1_fe_equal_varX(const secp256k1_feX *a, const secp256k1_feX *b) {
    secp256k1_feX na;
    secp256k1_fe_negateX(&na, a, 1);
    secp256k1_fe_addX(&na, b);
    return secp256k1_fe_normalizes_to_zero_varX(&na);
}

static int secp256k1_gej_eq_x_varX(const secp256k1_feX *x, const secp256k1_gejX *a) {
    secp256k1_feX r, r2;
    secp256k1_fe_sqrX(&r, &a->z); secp256k1_fe_mulX(&r, &r, x);
    r2 = a->x; secp256k1_fe_normalize_weakX(&r2);
    return secp256k1_fe_equal_varX(&r, &r2);
}

int secp256k1_fe_cmp_varX(secp256k1_feX *a, __constant secp256k1_feX *b) {
	int i;
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

static int secp256k1_ecdsa_sig_verifyX(global const secp256k1_ge_storageX *ctx, const secp256k1_scalarX *sigr, const secp256k1_scalarX *sigs,
										const secp256k1_geX *pubkey, const secp256k1_scalarX *message) 
{
    unsigned char c[32];
    secp256k1_scalarX u1, u2, sn;
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
	printf("\nG pr %ul\n", pr.y.n[1]);
    if (secp256k1_gej_is_infinityX(&pr)) {
        return 0;
    }
	printf("\nAfter IF");
    secp256k1_scalar_get_b32X(c, sigr);
	printf("\nGetGet");
    secp256k1_fe_set_b32XX(&xr, c);
	printf("\nSet %ul", xr.n[0]);
    if (secp256k1_gej_eq_x_varX(&xr, &pr)) {
        return 1;
    }
	printf("\nAfter IF2");
	if (secp256k1_fe_cmp_varX(&xr, &secp256k1_ecdsa_const_p_minus_orderX) >= 0) {
		return 0;
    }
    secp256k1_fe_addXX(&xr, &secp256k1_ecdsa_const_order_as_feX);
    if (secp256k1_gej_eq_x_varX(&xr, &pr)) {
        return 1;
    }
    return 0;
}

/////// K E R N E L S ///////
/////// K E R N E L S ///////
/////// K E R N E L S ///////
/////// K E R N E L S ///////


__kernel void secp256k1_ecdsa_verifyX(__global const secp256k1_ge_storageX* ctx, __global const secp256k1_ecdsa_signatureX *sig, 
										__global const unsigned char *msg32, __global const secp256k1_pubkeyX *pubkey, __global int *res) { 
	secp256k1_geX q;
    secp256k1_scalarX r, s, ret_sig_var;
    secp256k1_scalarX m;
    secp256k1_scalar_set_b32X(&m, msg32, NULL);
	
    secp256k1_ecdsa_signature_loadX(ctx, &r, &s, &sig[get_global_id(0)]);
	int load_res = secp256k1_pubkey_loadX(ctx, &q, pubkey);
	int tmp = (secp256k1_pubkey_loadX(ctx, &q, pubkey) && secp256k1_ecdsa_sig_verifyX(ctx, &r, &s, &q, &m));
	res[get_global_id(0)] = tmp;
}