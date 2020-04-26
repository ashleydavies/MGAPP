#ifndef FOP_H
#define FOP_H

static int masked_fop(int futex_op) { return futex_op & FUTEX_CMD_MASK; }

#define FUT_OP(OPLOWER,OP) static int is_futex_##OPLOWER(int futex_o) { \
        return masked_fop(futex_o) == FUTEX_##OP; \
    }

/*
Complete list of Futex operations defined in uapi/linux/futex.h:
*/

FUT_OP(wait,WAIT)
FUT_OP(wake,WAKE)
FUT_OP(fd,FD)
FUT_OP(requeue,REQUEUE)
FUT_OP(cmp_requeue,CMP_REQUEUE)
FUT_OP(wake_op,WAKE_OP)
FUT_OP(lock_pi,LOCK_PI)
FUT_OP(unlock_pi,UNLOCK_PI)
FUT_OP(trylock_pi,TRYLOCK_PI)
FUT_OP(wait_bitset,WAIT_BITSET)
FUT_OP(wake_bitset,WAKE_BITSET)
FUT_OP(wait_requeue_pi,WAIT_REQUEUE_PI)
FUT_OP(cmp_requeue_pi,CMP_REQUEUE_PI)

#endif