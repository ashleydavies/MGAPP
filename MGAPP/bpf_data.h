#ifndef BPF_DATA_H
#define BPF_DATA_H

///////////////////////////////////////////
// BPF DATA STRUCTURES
///////////////////////////////////////////

BPF_ARRAY(array_indexes, unsigned);


// For communication with core -> ring buffer
BPF_HASH(last_thread_operation, u32, u32);
#define LAST_OPERATION_UNKNOWN 0
#define LAST_OPERATION_FUTEX_WAIT 1
#define LAST_OPERATION_FUTEX_WAKE 2
#define LAST_OPERATION_IO 3

static void set_last_operation(u32 pid, u32 value) {
    last_thread_operation.insert(&pid, &value);
}

static void clear_last_operation(u32 pid) {
    last_thread_operation.delete(&pid);
}

static int get_last_operation(u32 pid) {
    u32 unknown = LAST_OPERATION_UNKNOWN;
    int *last_operation_value = last_thread_operation.lookup_or_init(&pid, &unknown);
    return *last_operation_value;
}

#endif
