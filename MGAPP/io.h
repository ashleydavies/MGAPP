#ifndef IO_H
#define IO_H

#include <uapi/linux/limits.h>

#include "bpf_data.h" //REMOVE

// Where the current index for the write calls array is stored in the general array_indexes map.
#define prev_write_calls_idx 0

typedef struct {
    int fd;
    u64 start_time_ns;
    u64 time_prediction;
    size_t count;
} curr_write_data;

typedef struct {
    u64 time_ns;
    size_t bytes;
} prev_write_data;

BPF_HASH(curr_write_calls, u32, curr_write_data);
BPF_ARRAY(prev_write_calls, prev_write_data, 128);
BPF_PERF_OUTPUT(open_events);

// Thread ID -> Current fd for that thread
BPF_HASH(curr_fd_thread, u32, u32);

// File descriptors can be re-used later when a file is closed, so we increment a number when closed
//   so that we can have a unique number to correspond to a given instance of a file descriptor.
BPF_HASH(fd_ids, u32, u64);

static inline void fd_ids_inc(u32 id) {
    u64 base = 1;
    u64 *val = fd_ids.lookup(&id);

    if (val == NULL) {
        fd_ids.insert(&id, &base);
    } else {
        (*val)++;
    }
}

static inline int fd_ids_get(u32 id) {
    u64 zero = 0;
    u64 *val = fd_ids.lookup_or_init(&id, &zero);
    return *val;
}

static inline void set_curr_fd_thread(u32 thread, u32 fd) {
    curr_fd_thread.update(&thread, &fd);
}

static inline int get_curr_fd_thread(u32 thread) {
    u32 *val = curr_fd_thread.lookup(&thread);
    if (val == NULL) return -1;
    return *val;
}

static void start_write(u32 pid, int fd, size_t count) {
    set_last_operation(pid, LAST_OPERATION_IO);
    set_curr_fd_thread(pid, fd);
#ifdef IO_DEBUG
    bpf_trace_printk("Set %d to IO\n", pid);
    bpf_trace_printk("Set to IO FD %d\n", fd);
#endif
    int zero = prev_write_calls_idx;
    u64 prediction = 0;
    unsigned *entries = array_indexes.lookup(&zero);
    if (entries != NULL && *entries > 2) {
        int loop_end = *entries;
        u64 min_time = 0;
        u64 max_time = 0;
        size_t min_write = 0xEFFFFFFF;
        size_t max_write = 0;

        size_t min_write_above = 0xEFFFFFFF;
        size_t max_write_below = 0;
        u64 min_time_above = 0;
        u64 max_time_below = 0;

        for (int i = 0; i < loop_end; i++) {
            prev_write_data *data = prev_write_calls.lookup(&i);
            if (data != NULL) {
                if (data->bytes > max_write) {
                    max_write = data->bytes;
                    max_time = data->time_ns;
                }
                if (data->bytes < min_write) {
                    min_write = data->bytes;
                    min_time = data->time_ns;
                }

                if ((data->bytes > max_write_below && data->bytes <= count) || (data->bytes == max_write_below && data->time_ns < max_time_below)) {
                    max_write_below = data->bytes;
                    max_time_below = data->time_ns;
                }
                if ((data->bytes < min_write_above && data->bytes >= count) || (data->bytes == min_write_above && data->time_ns > min_time_above)) {
                    min_write_above = data->bytes;
                    min_time_above = data->time_ns;
                }
            }
        }
        /*
        if (max_write_below == 0) {
            max_write_below = min_write;
            max_time_below = min_time;
        }
        if (min_write_above == 0xEFFFFFFF) {
            min_write_above = max_write;
            min_time_above = max_time;
        }
        */
        if (max_write_below != 0 && min_write_above != 0xEFFFFFFF) {
            u64 time_diff = min_time_above - max_time_below;
            size_t write_diff = min_write_above - max_write_below;
            int time_per_byte = (10000 * time_diff) / write_diff;
            u64 base_time = max_time_below - (time_per_byte * max_write_below) / 10000;
            prediction = base_time + (time_per_byte * count) / 10000;
        } else {
            u64 time_diff = max_time - min_time;
            size_t write_diff = max_write - min_write;
            int time_per_byte = (10000 * time_diff) / write_diff;
            u64 base_time = min_time - (time_per_byte * min_write) / 10000;
            prediction = base_time + (time_per_byte * count) / 10000;
        }
#ifdef IO_DEBUG
        bpf_trace_printk("Predicting: %d\n", prediction);
#endif

        //u64 a;
        //u64 b;
        //for (unsigned i = 0; i < *entries; i++) {
        //bpf_trace_printk("%u\n", i);
        //}
    }

    curr_write_data entry = {};
    entry.fd = fd;
    entry.start_time_ns = bpf_ktime_get_ns();
    entry.time_prediction = prediction;
    entry.count = count;
    curr_write_calls.insert(&pid, &entry);
}

static void end_write(u32 pid, int count) {
    curr_write_data *entry = curr_write_calls.lookup(&pid);
#ifdef IO_DEBUG
    bpf_trace_printk("IO Complete %d\n", count);
#endif
    if (entry != NULL) {
        if (count == entry->count) {
            u64 delta = bpf_ktime_get_ns() - entry->start_time_ns;

#ifdef IO_DEBUG
            bpf_trace_printk("Write complete %d\n", count);
            bpf_trace_printk("Took %d ns\n", delta);

            if (entry->time_prediction != 0) {
                bpf_trace_printk("Result was %dpct of the prediction\n", (100 * delta + entry->time_prediction / 2) / entry->time_prediction);
            }
#endif

            unsigned zero = prev_write_calls_idx;
            int *idx = array_indexes.lookup(&zero);
            if (idx != NULL) {
                // TODO: Circularify
                prev_write_data data = {};
                data.time_ns = delta;
                data.bytes = count;
                prev_write_calls.update(idx, &data);
                array_indexes.increment(zero);
            }
        } else {
            bpf_trace_printk("UNKNOWN BEHAVIOUR -- NOT ALL OF I/O WAS WRITTEN?\n");
        }
        curr_write_calls.delete(&pid);
    } else {
        bpf_trace_printk("WRITE ERROR - NO REGISTERED CURR_WRITE_DATA ENTRY?\n");
    }

    clear_last_operation(pid);
}

int kprobe____x64_sys_write(struct pt_regs *ctx, int fd, const void *buff, size_t count) { FILTER
    start_write(pid, fd, count);
    return 0;
}

int kretprobe__sys_write(struct pt_regs *ctx) { FILTER
    end_write(pid, PT_REGS_RC(ctx));
    return 0;
}

// optnone is required to disable optimisations and allow the løöp to work as expected
int kprobe____x64_sys_writev(struct pt_regs *ctx, int fd, const struct iovec *iov, int iovcnt) __attribute__ ((optnone)) { FILTER
    int write_amount = 0;

    for (int i = 0; i < UIO_MAXIOV; i++) {
        if (i >= iovcnt) break;
        write_amount += iov[i].iov_len;
    }

    start_write(pid, fd, write_amount);
    return 0;
}

int kretprobe__sys_writev(struct pt_regs *ctx) { FILTER
    end_write(pid, PT_REGS_RC(ctx));
    return 0;
}


typedef struct {
    int fd;
    size_t count;
} curr_read_data;

BPF_HASH(curr_read_calls, u32, curr_read_data);

static void start_read(u32 pid, int fd, size_t count) {
    set_last_operation(pid, LAST_OPERATION_IO);
    set_curr_fd_thread(pid, fd);

    #ifdef IO_DEBUG
    bpf_trace_printk("Set to IO (read) %d\n", count);
    bpf_trace_printk("Set to IO (read) FD %d\n", fd);
    #endif

    curr_read_data entry = {};
    entry.fd = fd;
    entry.count = count;
    curr_read_calls.insert(&pid, &entry);

//    tracking_thread_set_inactive(pid);
    set_curr_fd_thread(pid, fd);
}

static void end_read(void *ctx, u32 pid, int count) {
    curr_read_data *entry = curr_read_calls.lookup(&pid);
//    #ifdef IO_DEBUG
//    bpf_trace_printk("IO Complete (Read) %d\n", count);
//    #endif
    if (entry != NULL) {
        curr_read_calls.delete(&pid);
    } OR(ERROR_END_READ_NO_CALL_DATA)

//    tracking_thread_set_active(pid);
    clear_last_operation(pid);
}

int kprobe__ksys_read(struct pt_regs *ctx, int fd, void __user *buf, size_t count) { FILTER
    start_read(pid, fd, count);
    return 0;
}

//TRACEPOINT_PROBE(syscalls, sys_enter_read) { void*ctx=args; FILTER
//    start_read(pid, args->fd, args->count);
//    return 0;
//}

typedef struct {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    long ret;
} exit_read_args_t;

int read_exit_probe(exit_read_args_t *ctx) { FILTER
    end_read(ctx, pid, ctx->ret);
    return 0;
}

//int kretprobe____x64_sys_read(struct pt_regs *ctx) { FILTER
//    end_read(ctx, pid, PT_REGS_RC(ctx));
//    return 0;
//}

//int kprobe____x64_sys_readv(struct pt_regs *ctx, int fd, const struct iovec *iov, int iovcnt) __attribute__ ((optnone)) { FILTER
//    int read_amnt = 0;
//
//    for (int i = 0; i < UIO_MAXIOV; i++) {
//        if (i >= iovcnt) break;
//        read_amnt += iov[i].iov_len;
//    }
//
//    start_read(pid, fd, read_amnt);
//    return 0;
//}
//
//int kretprobe__sys_readv(struct pt_regs *ctx) { FILTER
//    end_read(ctx, pid, PT_REGS_RC(ctx));
//    return 0;
//}

/*
 * ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
               off_t offset);
ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt,
                off_t offset);
 */
int kprobe__sys_creat(struct pt_regs *ctx) { FILTER
    bpf_trace_printk("IGNORED SYSCALL: sys_creat\n");
    return 0;
}

typedef struct {
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    int __syscall_nr;
    int dfd;
    const char __user *filename;
    int flags;
    umode_t mode;
} sys_enter_openat_args;

typedef struct {
    u32 fd;
    u32 fd_id;
    char fname[NAME_MAX];
} open_event_t;


typedef struct {
    int dfd;
    const char *fname;
} openat_call_t;

BPF_HASH(openat_calls, u32, openat_call_t);

int kprobe____x64_sys_openat(struct pt_regs *ctx, int dfd, const char __user *filename) { FILTER
    openat_call_t call = {};
    call.dfd = dfd;
    call.fname = filename;

    if (openat_calls.lookup(&pid) != NULL) {
        ERROR_OPENAT_ALREADY_OPENING;
    }

    openat_calls.update(&pid, &call);
    return 0;
}

int kretprobe____x64_sys_openat(struct pt_regs *ctx) { FILTER
    openat_call_t *call_p = openat_calls.lookup(&pid);
    if (call_p == NULL) {
        ERROR_OPENAT_NO_ENTRY;
        return 0;
    }

    u32 return_val = PT_REGS_RC(ctx);
    openat_call_t call = *call_p;

    open_event_t event = {};
    bpf_probe_read(&event.fname, sizeof(event.fname), call.fname);
    event.fd = return_val;
    event.fd_id = fd_ids_get(return_val);

    open_events.perf_submit(ctx, &event, sizeof(event));
    openat_calls.delete(&pid);
    return 0;
}

BPF_HASH(ongoing_glibc_file_closes, u32, u32);
BPF_HASH(curr_close_calls, u32, u32);

int glibc_file_close(struct pt_regs *ctx) { FILTER
    u32 one = 1;
    ongoing_glibc_file_closes.update(&pid, &one);
    return 0;
}

int kprobe____close_fd(struct pt_regs *ctx, int *_, int n) { FILTER
    u32 *ongoing = ongoing_glibc_file_closes.lookup(&pid);
    if (ongoing == NULL) return 0;

    set_last_operation(pid, LAST_OPERATION_IO);
    set_curr_fd_thread(pid, n);
    curr_close_calls.update(&pid, &n);
    return 0;
}

// Actually bound to return of _IO_un_link because of the unreliableness of return probes
int glibc_file_close_ret(struct pt_regs *ctx) { FILTER
    u32 *ongoing = ongoing_glibc_file_closes.lookup(&pid);
    if (ongoing == NULL) return 0;
    ongoing_glibc_file_closes.delete(&pid);

    // File close -> increment the local file ID to correctly attribute file writes
#ifdef IO_DEBUG
    bpf_trace_printk("Closing finished for %d\n", pid);
#endif
    int *n = curr_close_calls.lookup(&pid);
    if (n == NULL) {
        ERROR_CLOSE_NO_FILE_DESCRIPTOR_SET;
        return 0;
    }

    fd_ids_inc(*n);
    clear_last_operation(pid);
    return 0;
}

struct in_addr {
    uint32_t       s_addr;
};

struct sockaddr_in {
    unsigned short sin_family;
    uint16_t       sin_port;
    struct in_addr sin_addr;
};

typedef struct {
    int          sock_fd;
    int          fd_id;
    unsigned int ip_addr;
} connect_event_t;

BPF_PERF_OUTPUT(connect_events);

// Assumes IPv4; this can be updated by testing the first entry of sockaddr_in to see if it's IPv4 or IPv6
// https://linux.die.net/man/7/ip
// https://beej.us/guide/bgnet/html/multi/sockaddr_inman.html
// TODO: Register return probe and test for success rather than assuming success (trivial)
int kprobe____sys_connect(struct pt_regs *ctx, int sock_fd, const struct sockaddr_in __user *sock_details) { FILTER
    connect_event_t event = {
        sock_fd, fd_ids_get(sock_fd), sock_details->sin_addr.s_addr
    };

    connect_events.perf_submit(ctx, &event, sizeof(connect_event_t));

    return 0;
}

static bool is_doing_io(u32 pid) {
    curr_read_data *read = curr_read_calls.lookup(&pid);
    curr_write_data *write = curr_write_calls.lookup(&pid);

    if (read != NULL) return true;
    if (write != NULL) return true;
    return false;
}

#endif
