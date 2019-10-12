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

#define SECP256K1_N_0 ((ulong)0xBFD25E8CD0364141UL)
#define SECP256K1_N_1 ((ulong)0xBAAEDCE6AF48A03BUL)
#define SECP256K1_N_2 ((ulong)0xFFFFFFFFFFFFFFFEUL)
#define SECP256K1_N_3 ((ulong)0xFFFFFFFFFFFFFFFFUL)

/* Limbs of 2^256 minus the secp256k1 order. */
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)

/* Limbs of half the secp256k1 order. */
#define SECP256K1_N_H_0 ((ulong)0xDFE92F46681B20A0UL)
#define SECP256K1_N_H_1 ((ulong)0x5D576E7357A4501DUL)
#define SECP256K1_N_H_2 ((ulong)0xFFFFFFFFFFFFFFFFUL)
#define SECP256K1_N_H_3 ((ulong)0x7FFFFFFFFFFFFFFFUL)

typedef struct {
    ulong d[4];
} secp256k1_scalar;

global void secp256k1_scalar_mul_512(ulong l[8], global secp256k1_scalar *a, global secp256k1_scalar *b) {
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

global int secp256k1_scalar_reduce(global secp256k1_scalar *r, unsigned int overflow) {
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


global int secp256k1_scalar_check_overflow(global secp256k1_scalar *a) {
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

global void secp256k1_scalar_reduce_512(global secp256k1_scalar *r, const ulong *l) {
    unsigned long long c;
    ulong c0, c1, c2;
    ulong n0 = l[4], n1 = l[5], n2 = l[6], n3 = l[7];
    ulong m0, m1, m2, m3, m4, m5;
    uint m6;
    ulong p0, p1, p2, p3;
    uint p4;

	
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
	
    c = p0 + (unsigned long long)SECP256K1_N_C_0 * p4;
	
    r->d[0] = c & 0xffffffffffffffffUL; c >>= 64;
    c += p1 + SECP256K1_N_C_1 * (unsigned long long)p4;
    r->d[1] = c & 0xffffffffffffffffUL; c >>= 64;
    c += p2 + (unsigned long long)p4;
    r->d[2] = c & 0xffffffffffffffffUL; c >>= 64;
    c += p3;
    r->d[3] = c & 0xffffffffffffffffUL; c >>= 64;

    secp256k1_scalar_reduce(r, c + secp256k1_scalar_check_overflow(r));
}

global void secp256k1_scalar_sqr_512(ulong l[8], global secp256k1_scalar *a) {

    ulong c0 = 0, c1 = 0;
    uint c2 = 0;

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


/////// K E R N E L S ///////
/////// K E R N E L S ///////
/////// K E R N E L S ///////
/////// K E R N E L S ///////


__kernel void secp256k1_scalar_mul(__global secp256k1_scalar *a, __global secp256k1_scalar *b, __global secp256k1_scalar *r) {
    ulong l[8];
    secp256k1_scalar_mul_512(l, a, b);
    secp256k1_scalar_reduce_512(r, l);
}

__kernel void secp256k1_scalar_sqr(__global secp256k1_scalar *a, __global secp256k1_scalar *r) {
    ulong l[8];
    secp256k1_scalar_sqr_512(l, a);
    secp256k1_scalar_reduce_512(r, l);
}

__kernel void secp256k1_scalar_is_zero(__global secp256k1_scalar *a, __global ulong *B) {
	B[0] = (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

