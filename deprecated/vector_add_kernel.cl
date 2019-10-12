
ulong adding(ulong a, ulong b, ulong c)
{
	return a+b+c;
}

typedef struct
{
    ulong m_low;
    ulong m_high;
} uint128_t;

uint128_t mul_64_64(ulong p_left, ulong p_right)
{
    uint128_t l_result;
    
    ulong a0 = p_left & 0xffffffffUL;
    ulong a1 = p_left >> 32;
    ulong b0 = p_right & 0xffffffffUL;
    ulong b1 = p_right >> 32;
    
    ulong m0 = a0 * b0;
    ulong m1 = a0 * b1;
    ulong m2 = a1 * b0;
    ulong m3 = a1 * b1;
    
    m2 += (m0 >> 32);
    m2 += m1;
    if(m2 < m1)
    { // overflow
        m3 += 0x100000000UL;
    }
    
    l_result.m_low = (m0 & 0xffffffffUL) | (m2 << 32);
    l_result.m_high = m3 + (m2 >> 32);
    
    return l_result;
}

uint128_t add_128_128(uint128_t a, uint128_t b)
{
    uint128_t l_result;
    l_result.m_low = a.m_low + b.m_low;
    l_result.m_high = a.m_high + b.m_high + (l_result.m_low < a.m_low);
    return l_result;
}

__kernel void vector_add(__global ulong *A, __global ulong *B, __global ulong *C, __global ulong *D) {
    ulong l_carry = 0;
    int i;
    for(i=0; i<4; ++i)
    {
    	ulong l_sum = adding(A[i], B[i], l_carry);
        if(l_sum != A[i]) {
            l_carry = (l_sum < A[i]);
        }
        C[i] = l_sum;
    }
    
   D[0] = l_carry;
}



__kernel void vector_sub(__global ulong *A, __global ulong *B, __global ulong *C, __global ulong *D) {
    //ulong c[4];
    ulong l_borrow = 0;
    int i;
    for(i=0; i<4; ++i)
    {
        ulong l_diff = A[i] - B[i] - l_borrow;
        if(l_diff != A[i])
            l_borrow = (l_diff > A[i]);
        C[i] = l_diff;
    }
    D[0] = l_borrow;
}

__kernel void vli_mult(__global ulong *p_result, __global ulong *p_left, __global ulong *p_right)
{
    uint128_t r01; 
    r01.m_low = 0;
    r01.m_high = 0;
    ulong r2 = 0;
    
    uint i, k;
    
    
    for(k=0; k < 4*2 - 1; ++k)
    {
        uint l_min;
        if( k < 4)
          l_min = 0; 
        else
          l_min = (k + 1) - 4;
        for(i=l_min; i<=k && i<4; ++i)
        {
            uint128_t l_product = mul_64_64(p_left[i], p_right[k-i]);
            r01 = add_128_128(r01, l_product);
            r2 += (r01.m_high < l_product.m_high);
        }
        p_result[k] = r01.m_low;
        r01.m_low = r01.m_high;
        r01.m_high = r2;
        r2 = 0;
    }
    
    p_result[4*2 - 1] = r01.m_low;
}


global void vli_set(global ulong *p_dest,global ulong *p_src)
{
    uint i;
    for(i=0; i<4; ++i)
        p_dest[i] = p_src[i];
}

ulong vli_lshift(ulong *p_result,ulong *p_in, uint p_shift)
{
    ulong l_carry = 0;
    uint i;
    for(i = 0; i < 4; ++i)
    {
        ulong l_temp = p_in[i];
        p_result[i] = (l_temp << p_shift) | l_carry;
        l_carry = l_temp >> (64 - p_shift);
    }
    
    return l_carry;
}

inline ulong vli_add(global ulong *p_result, global ulong *p_left, ulong *p_right)
{
    ulong l_carry = 0;
    uint i;
    for(i=0; i<4; ++i)
    {
        ulong l_sum = p_left[i] + p_right[i] + l_carry;
        if(l_sum != p_left[i])
        {
            l_carry = (l_sum < p_left[i]);
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}

inline ulong vli_sub(global ulong *p_result, global ulong *p_left, ulong *p_right)
{
    ulong l_borrow = 0;
    uint i;
    for(i=0; i<4; ++i)
    {
        ulong l_diff = p_left[i] - p_right[i] - l_borrow;
        if(l_diff != p_left[i])
        {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}

int vli_cmp(ulong *p_left, global ulong *p_right)
{
    int i;
    for(i = 4-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}


__kernel void mmod_fast(__global ulong *p_result,__global ulong *p_product)
{
    ulong l_tmp[4];
    int l_carry;
    
    // t 
    vli_set(p_result, p_product);
    
    // s1 
    l_tmp[0] = 0;
    l_tmp[1] = p_product[5] & 0xffffffff00000000UL;
    l_tmp[2] = p_product[6];
    l_tmp[3] = p_product[7];
    l_carry = vli_lshift(l_tmp, l_tmp, 1);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    // s2 
    l_tmp[1] = p_product[6] << 32;
    l_tmp[2] = (p_product[6] >> 32) | (p_product[7] << 32);
    l_tmp[3] = p_product[7] >> 32;
    l_carry += vli_lshift(l_tmp, l_tmp, 1);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    // s3 
    l_tmp[0] = p_product[4];
    l_tmp[1] = p_product[5] & 0xffffffff;
    l_tmp[2] = 0;
    l_tmp[3] = p_product[7];
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    // s4 
    l_tmp[0] = (p_product[4] >> 32) | (p_product[5] << 32);
    l_tmp[1] = (p_product[5] >> 32) | (p_product[6] & 0xffffffff00000000UL);
    l_tmp[2] = p_product[7];
    l_tmp[3] = (p_product[6] >> 32) | (p_product[4] << 32);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    // d1 
    l_tmp[0] = (p_product[5] >> 32) | (p_product[6] << 32);
    l_tmp[1] = (p_product[6] >> 32);
    l_tmp[2] = 0;
    l_tmp[3] = (p_product[4] & 0xffffffff) | (p_product[5] << 32);
    l_carry -= vli_sub(p_result, p_result, l_tmp);
    
    // d2 
    l_tmp[0] = p_product[6];
    l_tmp[1] = p_product[7];
    l_tmp[2] = 0;
    l_tmp[3] = (p_product[4] >> 32) | (p_product[5] & 0xffffffff00000000UL);
    l_carry -= vli_sub(p_result, p_result, l_tmp);
    
    //d3 
    l_tmp[0] = (p_product[6] >> 32) | (p_product[7] << 32);
    l_tmp[1] = (p_product[7] >> 32) | (p_product[4] << 32);
    l_tmp[2] = (p_product[4] >> 32) | (p_product[5] << 32);
    l_tmp[3] = (p_product[6] << 32);
    l_carry -= vli_sub(p_result, p_result, l_tmp);
    
    //d4 
    l_tmp[0] = p_product[7];
    l_tmp[1] = p_product[4] & 0xffffffff00000000UL;
    l_tmp[2] = p_product[5];
    l_tmp[3] = p_product[6] & 0xffffffff00000000UL;
    l_carry -= vli_sub(p_result, p_result, l_tmp);
    
    ulong curve_p[4];
    curve_p[0] = 0xffffffffffffffffUL;
    curve_p[1] = 0x00000000ffffffffUL;
    curve_p[2] = 0x0000000000000000UL;
    curve_p[3] = 0xffffffff00000001UL;  
    
    if(l_carry < 0)
    {
        while(l_carry < 0)
        {
            l_carry += vli_add(p_result, p_result, curve_p); //TODO: last arg is curve_p its fix num now
        } 
    }
    else
    {
        while(l_carry || vli_cmp(curve_p, p_result) != 1) //TODO: first arg is curve_p its fix num now
        {
            l_carry -= vli_sub(p_result, p_result, curve_p); //TODO: last arg is curve_p its fix num now
        }
    }
}

//__kernel void modMult_fast(__global ulong *p_result, __global ulong *p_left, __global ulong *p_right)
//{
//    ulong l_product[2 * 4];
//    vli_mult(l_product, p_left, p_right);
//    mmod_fast(p_result, l_product);
//}

