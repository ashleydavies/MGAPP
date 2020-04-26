#ifndef SCHEDULING_H
#define SCHEDULING_H

#include "thread_tracking.h" //REMOVE

#include "futex.h" //REMOVE

typedef struct {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
} sched_switch_args;

typedef struct {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char comm[16];
    pid_t pid;
    int prio;
} sched_process_exit_args;

typedef struct {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    char comm[16];
    pid_t pid;
    int prio;
    int success;
    int target_cpu;
} sched_waking_args;

static int scheduling_sched_process_exit(sched_process_exit_args *ctx) { FILTER
    tracking_stop_tracking_thread(ctx->pid);
    return 0;
}

// Waking is called when the thread is being woken; from the waking context
// TODO: Does this filtering logic make sense? I don't fully understand it anymore
static int scheduling_sched_waking(sched_waking_args *ctx) {
    u64 pidtgid = bpf_get_current_pid_tgid();
    u32 pid = pidtgid;

    if (!tracking_thread_is_tracked(ctx->pid) || !(ctx->success)) {
        return 0;
    }

    u32 pid_lookup = ctx->pid;
    void *futex_waiting_addr_p = futex_waiting_h.lookup(&pid_lookup);

    if (futex_waiting_addr_p != NULL) {
        futex_waiting_t *waiting_info = (futex_waiting_t*) futex_waiting_addr_p;

#ifdef SCHED_DEBUG
        bpf_trace_printk("Waking on futex %p\n", waiting_info->futex_uaddr);
#endif

        // We should have already have a FUTEX_WAKE operation, so error in the case where we don't
        u32 *uaddr = waiting_info->futex_uaddr;
        void *futex_waking_addr_p = futex_waking_h.lookup(&uaddr);
        if (futex_waking_addr_p != NULL || pid == 0) {
#ifdef SCHED_DEBUG
            bpf_trace_printk("Identified the cause of a futex_wait for pid %d\n", ctx->pid);
#endif
            u64 time = bpf_ktime_get_ns() - waiting_info->wait_start_ns;
            u32 tgid = pidtgid >> 32;
            send_futex_wake_operation(ctx, uaddr, ctx->pid, tgid, pid, time);
        } OR(ERROR_FUTEX_UNASSOCIATED_THREAD_WOKEN)

        futex_waiting_h.delete(&pid_lookup);
        clear_last_operation(pid_lookup);
        set_last_operation(pid, LAST_OPERATION_FUTEX_WAKE);
    }
    return 0;
}

#endif
