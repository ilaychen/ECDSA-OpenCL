/* Computes p_result = p_left + p_right, returning carry. Can modify in place. */
__kernel void vli_add_cl(__global ulong *p_result, __global ulong *p_carry, __global const ulong *p_left, __global ulong *p_right) {
    ulong l_carry = 6;
    int i;
    *p_result = l_carry;
    //for(i=0; i<4; ++i)
    //{
        //ulong l_sum = p_left[i] + p_right[i] + l_carry;
    //    if(l_sum != p_left[i])
    //    {
    //        l_carry = (l_sum < p_left[i]);
    //    }
        //p_result[i] = l_sum;//l_sum;
    //}
    //*p_carry  = l_carry;
}
