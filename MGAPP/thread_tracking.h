#ifndef THREAD_TRACKING_H
#define THREAD_TRACKING_H

#define SAFE(ptr) if (ptr == NULL) return 0;

// Thread ID -> Set/Unset (For keeping track of which threads we care about; updated on clone / exit)
// TODO: Not properly updated on exit... other processes might hijack it unintentionally...
BPF_HASH(thread_pids, u32, int);
BPF_HASH(active_thread_count, u32, u32, 1);
BPF_ARRAY(total_thread_count, u32, 1);              // Stores the total thread count (parent not included)

static inline int tracking_thread_active_count() {
    u32 zero = 0;
    int *active = active_thread_count.lookup_or_init(&zero, &zero);
    if (active == NULL) return 0;
#ifdef TRACKING_DEBUG
    bpf_trace_printk("There are currently %d active threads\n", *active);
#endif
    return *active;
}

static inline int tracking_thread_total_count() {
    u32 zero = 0;
    int *total = total_thread_count.lookup_or_init(&zero, &zero);
    if (total == NULL) return 0;
#ifdef TRACKING_DEBUG
    bpf_trace_printk("There are currently %d total threads\n", *total);
#endif
    return *total;
}

static inline int tracking_thread_is_tracked(u32 pid) {
    return thread_pids.lookup(&pid) != NULL;
}

static inline int tracking_thread_is_tracked_and_active(u32 pid) {
    int *active = thread_pids.lookup(&pid);
    return active != NULL && *active;
}

static inline int tracking_thread_is_tracked_and_inactive(u32 pid) {
    int *active = thread_pids.lookup(&pid);
    return active != NULL && !(*active);
}

#ifdef PROG_PID
static inline int tracking_thread_should_be_tracked(u32 pid, u32 tgid, char *comm) {
    return pid == PROG_PID || thread_pids.lookup(&pid) != NULL;
}
#elif defined(PROG_COMM)
static inline int tracking_thread_should_be_tracked(u32 pid, u32 tgid, char *comm) {
    if (thread_pids.lookup(&pid) != NULL) return true;

    char name[] = PROG_COMM;

    for (int i = 0; i < sizeof(name); i++) {
        if (name[i] != comm[i]) return false;
    }

    return true;
}
#else
// This function will prevent compilation and exists to ensure either PROG_COMM or PROG_PID is provided.
static inline int tracking_thread_should_be_tracked(u32 _, u32 _, char *_) {
    no_compile
}
#endif

// The returns of these functions are not used; they are just because lookup_or_init requires a context which
//   is capable of returning an int.
// TODO: All tracked threads are assumed to initially be running; is this necessarily true?
static int tracking_track_thread(u32 pid) {
    int zero = 0;
    int one = 1;
    thread_pids.update(&pid, &one);

    int *active = active_thread_count.lookup_or_init(&zero, &zero);
    lock_xadd(active, 1);
    int *total = total_thread_count.lookup_or_init(&zero, &zero);
    lock_xadd(total, 1);
    return 0;
}

static int tracking_stop_tracking_thread(u32 pid) {
    int *val = thread_pids.lookup(&pid);
    if (val == NULL) return 0;

    u32 zero = 0;

#ifdef TRACKING_DEBUG
    bpf_trace_printk("Terminating %d\n", pid);
#endif

    if (*val) {
        int *active = active_thread_count.lookup(&zero); SAFE(active);
#ifdef TRACKING_DEBUG
        bpf_trace_printk("Setting %d to inactive\n", pid);
#endif
        lock_xadd(active, -1);
    }

    thread_pids.delete(&pid);

    int *total = total_thread_count.lookup(&zero); SAFE(total);
    lock_xadd(total, -1);
    return 0;
}

static int tracking_thread_set_active(u32 pid) {
    int *curr = thread_pids.lookup(&pid);
    if (curr == NULL) return 0;

    // If it is already marked as active, skip this step
    if (*curr) return 0;

#ifdef TRACKING_DEBUG
    bpf_trace_printk("Setting %d to active\n", pid);
#endif

    int val = 1;
    thread_pids.update(&pid, &val);

    u32 zero = 0;
    int *active = active_thread_count.lookup(&zero); SAFE(active);
    lock_xadd(active, 1);
    return 0;
}

static int tracking_thread_set_inactive(u32 pid) {
    int *curr = thread_pids.lookup(&pid);
    if (curr == NULL) return 0;
    if (!*curr) return 0;

#ifdef TRACKING_DEBUG
    bpf_trace_printk("Setting %d to inactive\n", pid);
#endif

    int val = 0;
    thread_pids.update(&pid, &val);

    int *active = active_thread_count.lookup(&val); SAFE(active);
    lock_xadd(active, -1);
    return 0;
}


#endif
