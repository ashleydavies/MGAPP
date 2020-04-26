#ifndef HELPERS_H
#define HELPERS_H

struct error_event_t {
    u32 error;
};

BPF_PERF_OUTPUT(error_events);

// C is a beautiful language
#define OR(E) else { E; }
#define ERROR_UNKNOWN_FUTEX_OP error(ctx, 1)
#define ERROR_FUTEX_WAIT_ALREADY_WAITING error(ctx, 2)
#define ERROR_FUTEX_WAKE_ALREADY_WAKING error(ctx, 3)
#define ERROR_FUTEX_UNASSOCIATED_THREAD_WOKEN error(ctx, 4)
#define ERROR_NEW_THREAD_DISCOVERED_TRACKING error(ctx, 5)
#define ERROR_FUTEX_RET_WITHOUT_CALL error(ctx, 6)
#define ERROR_UNABLE_TO_ACCESS_KNOWN_ARRAY_LOCATION error(ctx, 7)
#define ERROR_OPENAT_ALREADY_OPENING error(ctx, 8)
#define ERROR_OPENAT_NO_ENTRY error(ctx, 9)
#define ERROR_END_READ_NO_CALL_DATA error(ctx, 10)
#define ERROR_CLOSE_NO_FILE_DESCRIPTOR_SET error(ctx, 11)

// Outputs an error code to user-space
static void error(void *ctx, int n) {
    bpf_trace_printk("Error %d\n", n);
    struct error_event_t error_event = {n};
    error_events.perf_submit(ctx, &error_event, sizeof(error_event));
}


#endif
