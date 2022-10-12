#ifndef __THREAD_FIXED_POINT_H
#define __THREAD_FIXED_POINT_H

/* Basic definitions of fixed point. */
typedef int fp;

/* 14 LSB used for fractional part. */
#define FP_Q 14

/* Convert integer n to fiexed point. */
#define FP_INT_TO_FP(n) ((n) << FP_Q)

/* Convert fixed point x to integer (round to zero). */
#define FP_ROUND_TO_ZERO(x) ((x) >> FP_Q)

/* Convert fixed point x to integer (round to nearest integer). */
#define FP_ROUND_TO_NEARESET(x)                                               \
  ((x) >= 0 ? ((x + (1 << (FP_Q >> 1))) >> FP_Q)                              \
            : ((x - (1 << (FP_Q >> 1))) >> FP_Q))

/* Add two fixed point x and y. */
#define FP_ADD(x, y) ((x) + (y))

/* Subtract two fixed point y from x. */
#define FP_SUB(x, y) ((x) - (y))

/* Add fixed point x and integer n to a fixed point. */
#define FP_ADD_MIXED(x, n) ((x) + ((n) << FP_Q))

/* Subtract integer n from fixed point x to a fixed point.*/
#define FP_SUB_MIXED(x, n) ((x) - ((n) << FP_Q))

/* Multiply two fixed point x by y. */
#define FP_MUL(x, y) ((fp)((((int64_t) x) * y) >> FP_Q))

/* Multiply fixed point x by integer n. */
#define FP_MUL_MIXED(x, n) ((x) * (n))

/* Divide two fixed point x by y. */
#define FP_DIV(x, y) ((fp)((((int64_t) x) >> FP_Q) / y))

/* Divide fixed point x by integer n. */
#define FP_DIV_MIXED(x, n) ((x) / (n))

#endif /* thread/fixed_point.h */