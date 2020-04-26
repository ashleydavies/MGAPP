#ifndef FUTEX_H
#define FUTEX_H

#include "bpf_data.h" //REMOVE

typedef struct {
    u32 event_id;
    u64 stack_id;
    u32 tgid;
    u32 pid;
    int *futex_uaddr;
} futex_wait_event_t;

typedef struct {
    u32 event_id;
    u64 stack_id;
    u32 tgid;
    u32 waking_pid;
    u32 woken_pid;
    int *futex_uaddr;
    u64 sleep_time;
} futex_wake_event_t;

typedef struct {
    int* futex_uaddr;
    u64 wait_start_ns;
} futex_waiting_t;

typedef struct {
    u32 *uaddr;
} curr_futex_data;

// An incrementing counter for each thread
BPF_HASH(futex_inc_counter_h, u32, u64);
// This stores a copy of the _woken_ thread's inc_counter value for the _waker_ thread.
// Allowing a sched_switch to find the relevant stack trace pair
BPF_HASH(futex_wake_id_h, u32, u64);

// Get a unique identifier for a given thread
// Useful for, e.g., numbering events from that thread.
static int futex_get_thread_event_count(u32 thread) {
    u64 zero = 0;
    u64 *val = futex_inc_counter_h.lookup_or_init(&thread, &zero);

    return *val;
}

// Increments the thread event counter and returns the old value
static int futex_inc_thread_event_count(u32 thread) {
    u64 zero = 0;

    u64 *val = futex_inc_counter_h.lookup_or_init(&thread, &zero);
    u64 old_value = *val;
    (*val)++;

    return old_value;
}

static int futex_get_wake_event_id(u32 thread) {
    u64 zero = 0;
    u64 *val = futex_wake_id_h.lookup_or_init(&thread, &zero);

    return *val;
}

static int futex_set_wake_event_id(u32 thread_waking, u32 thread_being_woken) {
    u64 value = futex_get_thread_event_count(thread_being_woken);
    futex_wake_id_h.update(&thread_waking, &value);
    return 0;
}

// Thread ID -> Futex it's waiting on
BPF_HASH(futex_waiting_h, u32, futex_waiting_t);

// Set temporarily when a thread begins waking another via FUTEX_WAKE;
// Futex Addr -> Waking thread
BPF_HASH(futex_waking_h, u32*, u32);

// Ongoing futex call data; pid -> call data
BPF_HASH(curr_futex_wake_calls, u32, curr_futex_data);

BPF_STACK_TRACE(futex_stack_traces, 4086);

// FUTEX EVENTS
BPF_PERF_OUTPUT(futex_wait_events);
BPF_PERF_OUTPUT(futex_wake_events);

// Called from scheduling.h
static inline void send_futex_wake_operation(void *ctx, int *futex_uaddr, u32 pid_being_woken, u32 tgid, u32 waking_pid, u64 sleep_time) {
    futex_wake_event_t wake_event = {};
    wake_event.tgid = tgid;
    wake_event.event_id = futex_get_thread_event_count(pid_being_woken);
    wake_event.woken_pid = pid_being_woken;
    wake_event.waking_pid = waking_pid;
    wake_event.futex_uaddr = futex_uaddr;
    wake_event.sleep_time = sleep_time;
    wake_event.stack_id = futex_stack_traces.get_stackid(ctx, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);

    futex_wake_events.perf_submit(ctx, &wake_event, sizeof(wake_event));

    // Store this information locally to pull it out if we get a critical stack trace!
    futex_set_wake_event_id(waking_pid, pid_being_woken);
}

// TODO: Currently only supports one waker at a time; should work for the vast majority of applications I imagine
int kprobe__futex_wake(struct pt_regs *ctx, u32 *uaddr) { FILTER
#ifdef FUTEX_DEBUG
    bpf_trace_printk("Entering futex wake\n");
#endif
    set_last_operation(pid, LAST_OPERATION_FUTEX_WAKE);

    if (curr_futex_wake_calls.lookup(&pid) != NULL) {
        futex_waking_h.delete(&uaddr);
    }

    if (futex_waking_h.lookup(&uaddr) != NULL) {
        futex_waking_h.delete(&uaddr);
    }

    curr_futex_wake_calls.insert(&pid, &(curr_futex_data){ uaddr });
    futex_waking_h.insert(&uaddr, &pid);

    return 0;
}

// Required to delete the futex_waking_h entry; not deleted by sched_waking as it may wake multiple threads
int kretprobe__futex_wake(struct pt_regs *ctx) { FILTER
#ifdef FUTEX_DEBUG
    if (PT_REGS_RC(ctx) > 0) bpf_trace_printk("Returned from futex wake, waking %d\n", PT_REGS_RC(ctx));
#endif
    curr_futex_data *call_data_p = curr_futex_wake_calls.lookup(&pid);
    if (call_data_p != NULL) {
        u32* uaddr = call_data_p->uaddr;
        futex_waking_h.delete(&uaddr);
    } else {
        ERROR_FUTEX_RET_WITHOUT_CALL;
    }
    curr_futex_wake_calls.delete(&pid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_futex) { void*ctx=args; FILTER
    clear_last_operation(pid);
    return 0;
}


int kprobe__futex_wait(struct pt_regs *ctx, u32 *uaddr) { FILTER
    // Increment the event counter to associate stack traces correctly
    futex_inc_thread_event_count(pid);

    // If this thread isn't already regarded as waiting on a Futex, set it up -- otherwise, something weird has happened
    //  -- probably, it woke up with a mechanism we aren't tracking or events are arriving out of order
    if (futex_waiting_h.lookup(&pid) != NULL) {
        futex_waiting_h.delete(&pid);
        ERROR_FUTEX_WAIT_ALREADY_WAITING;
    }

    futex_waiting_t waiting_struct = {
        uaddr,
        bpf_ktime_get_ns()
    };
    futex_waiting_h.insert(&pid, &waiting_struct);

    futex_wait_event_t wait_event = {};
    wait_event.event_id = futex_get_thread_event_count(pid);
    wait_event.pid = pid;
    wait_event.futex_uaddr = uaddr;
    wait_event.tgid = tgid;
    wait_event.stack_id = futex_stack_traces.get_stackid(ctx, BPF_F_USER_STACK | BPF_F_REUSE_STACKID);

    futex_wait_events.perf_submit(ctx, &wait_event, sizeof(wait_event));

    return 0;
}

// Called on every futex wait re-entry; more reliable than kprobe__futex_wait
int kprobe__futex_wait_setup(struct pt_regs *ctx, u32 *uaddr) { FILTER
#ifdef FUTEX_DEBUG
    bpf_trace_printk("Entering futex wait\n");
#endif
    set_last_operation(pid, LAST_OPERATION_FUTEX_WAIT);

    return 0;
}

#endif
