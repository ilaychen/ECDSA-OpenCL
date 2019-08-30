
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
    //ulong c[4];
    uint128_t try;
    try.m_low = A[0];
    try.m_high = A[0];
    ulong l_carry = 0;
    int i;
    for(i=0; i<4; ++i)
    {
    	ulong l_sum;
    	if (i==0)
        	l_sum = adding(try.m_low, B[i], l_carry);
        else
        	l_sum = adding(A[i], B[i], l_carry);
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
    //for(i=0; i<4; ++i)
    //{
    	//C[i] = c[i];
    //}
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

