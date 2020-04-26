#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wall"
#pragma clang diagnostic ignored "-Wextra"
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>
#include <linux/sched.h>
#include <linux/types.h>
#pragma clang diagnostic pop

#include "thread_tracking.h" //REMOVE
#include "futex.h" //REMOVE


//Structure to pass information from the kernel probe to the user probe
struct key_t {
    u32 tid;            // Thread ID
    u32 tgid;           // Parent thread ID
    u64 cm;             // CMetric
    int source;         // 0 - sampling, 1 - critical time slice, 2 - non-critical time slice
    int stackid;
    int store_stackTop;
    int last_causal_event; // See bpf_data.h
    int event_metadata;    // Allows extra metadata (e.g. for futex events it's the event ID)
    int event_metadata_2;  // Ditto
};

BPF_HASH(tsp, u32, u64, 1);            // Stores timestamp of previous event

BPF_HASH(global_CM, u32, u64, 1);      // Keeps track of cumulative sum of CMetric - Global
BPF_PERCPU_ARRAY(local_CM, u64, 1);    // To store the snapshot of global_CM when a thread is switched in
BPF_HASH(CM_hash, u32, u64);           // Criticality Metric hash map for each thread
BPF_HASH(GLOBAL_WT_TC, u32, u64, 1);   // Stores the cumulative sum of weighted thread Count - Global
BPF_PERCPU_ARRAY(LOCAL_WT_TC, u64, 1); // Stores the snapshot of GLOBAL_WT_TC - CPU Local
BPF_PERCPU_ARRAY(inTS, u64, 1);        // Store the time at which a thread was switched in - CPU Local
BPF_PERF_OUTPUT(gapp_crit_events);     // Buffer to write event details
BPF_STACK_TRACE(stacktraces, 4086);

/*sched_switch_args {
    // from /sys/kernel/debug/tracing/events/sched/sched_switch/format
    u64 __unused__;
    char prev_comm[16];
    pid_t prev_pid;
    int prev_prio;
    long prev_state;
    char next_comm[16];
    pid_t next_pid;
    int next_prio;
};
*/

int do_perf_event(struct bpf_perf_event_data *ctx) { FILTER
    int active_count = tracking_thread_active_count();
    int total_count = tracking_thread_total_count();

    if ((active_count <= (total_count / STACK_FILTER)) || active_count == 1) {
        //if(STACK_FILTER_SAMPLER){

        struct key_t key = {};
        key.tid = pid;
        key.tgid = tgid;
        key.cm = 0;
        key.source = 0;
        if (pid != tgid) { //If not parent thread
            key.stackid = PT_REGS_IP(&ctx->regs); //Get the instruction pointer
            gapp_crit_events.perf_submit(ctx, &key, sizeof(key)); //Write details to the ring buffer
        }
    }
    return 0;
}

static int core_sched_wakeup(sched_waking_args *args) {
    u32 targetID, zero32 = 0, status, one32 = 1;

    //Check if thread being woken up belongs to the application
    if (!tracking_thread_is_tracked(args->pid)) {
        return 0;
    }

    /////////////////////////////////////////////////////////////////////

    if (args->success) { //If waking was successful
        int prev_thread_count = tracking_thread_active_count();

        if (tracking_thread_is_tracked_and_inactive(targetID)) {
//            if (!is_doing_io(targetID)) {
                tracking_thread_set_active(targetID);
//            }
        }
    }
    return 0;
}

//Tracepoint probe for the Sched_Switch tracepoint

static int core_sched_switch(sched_switch_args *args) {
    u32 one32 = 1, arrayKey = 0, zero32 = 0;
    u64 zero64 = 0;

    //Copy data to BPF stack
    u32 next_pid = args->next_pid;
    u32 prev_pid = args->prev_pid;

    volatile int prev = tracking_thread_is_tracked(prev_pid);
    int next = tracking_thread_is_tracked(next_pid);

    //Return if the switching threads do not belong to the application
    if (!prev && !next) {
        return 0;
    }

#ifdef SCHED_DEBUG // Although this code is not very reliable since it itself -causes- sched_switch events (printing)
    if (prev && !next) {
        bpf_trace_printk("Descheduling %d\n", prev_pid);
    }

    if (!prev) {
        bpf_trace_printk("Rescheduling %d\n", next_pid);
    }
#endif

    //////////////////////////////////////////////////////////////////////

    //Calculate values common for all switching events

    u64 interval, intervalCM;
    u64 *oldTS = tsp.lookup_or_init(&arrayKey, &zero64);

    if (!oldTS) {
        return 0;
    }

    u64 tempTS;
    bpf_probe_read(&tempTS, sizeof(tempTS), oldTS); //Copy Old time from bpf map to local variable
    u64 newTS = bpf_ktime_get_ns();
    tsp.update(&arrayKey, &newTS);      //Update time stamp

    int prev_tc = tracking_thread_active_count();

    if (newTS < tempTS) {//Very rarely, event probes are triggered out of order, which are ignored
        return 0;
    }

    if (tempTS == 0
        || prev_tc == 0) { //If first event or no active threads in during the previous interval, prev interval = 0
        interval = 0;
    } else {
        interval = (newTS - tempTS);
    } //Switching interval

    u64 *ptr_globalCM = global_CM.lookup_or_init(&arrayKey, &zero64);

    if (!ptr_globalCM) {
        return 0;
    }

    //Calculate the CMetric for previous interval and add it to global_CM
    if (interval != 0) {
        intervalCM = interval / prev_tc;
        lock_xadd(ptr_globalCM, intervalCM);
    }

    //Calculate weighted thread count for previous interval
    u64 wt_threadCount = (interval) * prev_tc;
    u64 *g_wt_threadCount = GLOBAL_WT_TC.lookup_or_init(&arrayKey, &zero64);
    if (!g_wt_threadCount) {
        return 0;
    }
    lock_xadd(g_wt_threadCount, wt_threadCount); //Add to global weighted thread count

    //////////////////////////////////////////////////////////////////////

    //If previous thread was a peer thread
    if (prev) {

        // Decrement active thread count only if thread switched out is not in RUNNING (0) state
        if (args->prev_state != TASK_RUNNING) {
            tracking_thread_set_inactive(prev_pid);
        }

        u64 temp;
        //Get updated CM
        bpf_probe_read(&temp, sizeof(temp), ptr_globalCM);

        //Get snapshot of global_CM which was stored in local_CM when prev_pid was switched in
        u64 *cpuCM = local_CM.lookup_or_init(&arrayKey, &zero64);

        if (!cpuCM) {
            return 0;
        }

        //Update the CM of the thread by adding the CM for the time slice
        u64 updateCM = temp - (*cpuCM);
        u64 *tCM = CM_hash.lookup_or_init(&prev_pid, &zero64);
        if (!tCM) {
            return 0;
        }
        *tCM = *tCM + updateCM;

        //Get LOCAL_WT_TC, the thread's weighted threadCount at the time it was switched in.
        u64 *t_wt_threadCount;
        t_wt_threadCount = LOCAL_WT_TC.lookup_or_init(&arrayKey, &zero64);
        if (!t_wt_threadCount) {
            return 0;
        }

        u64 temp_g_wt_threadCount, temp_t_wt_threadCount;

        bpf_probe_read(&temp_g_wt_threadCount, sizeof(temp_g_wt_threadCount), g_wt_threadCount);
        bpf_probe_read(&temp_t_wt_threadCount, sizeof(temp_t_wt_threadCount), t_wt_threadCount);

        //Reset the per-CPU CMetric counter
        local_CM.update(&arrayKey, &zero64);
        //Reset local weighted ThreadCount counter
        LOCAL_WT_TC.update(&arrayKey, &zero64);

        //Get time when this thread was switched in
        oldTS = inTS.lookup_or_init(&arrayKey, &zero64);
        if (!oldTS) {
            return 0;
        }

        u64 switch_in_time, timeSlice;
        bpf_probe_read(&switch_in_time, sizeof(switch_in_time), oldTS);
        timeSlice = (newTS - switch_in_time);
        //Reset switch in time
        inTS.update(&arrayKey, &zero64);

        u32 total_count = tracking_thread_total_count();

        //Calculate the average number of threads
        u32 ratio = (temp_g_wt_threadCount - temp_t_wt_threadCount) / timeSlice;

        struct key_t key = {};
        key.tid = prev_pid;
        key.tgid = bpf_get_current_pid_tgid() >> 32;
        key.cm = updateCM;

        //If thread_avg < threshold and not parent thread
        if ((ratio <= (total_count / STACK_FILTER) || ratio == 1) /*&& key.tid != key.tgid */) {
            //if( (ratio <= totalCount/2 || ratio == 1) && key.tid != key.tgid){ //If thread_avg < threshold and not parent thread
            key.stackid = stacktraces.get_stackid(args, BPF_F_REUSE_STACKID | BPF_F_USER_STACK);
            key.source = 1;
        } else {
            key.stackid = 0;
            key.source = 2;
        }

        key.last_causal_event = get_last_operation(prev_pid);
        key.event_metadata = 0;

        if (key.last_causal_event == LAST_OPERATION_FUTEX_WAIT) {
            key.event_metadata = futex_get_thread_event_count(prev_pid);
        } else if (key.last_causal_event == LAST_OPERATION_FUTEX_WAKE) {
            // Find the pid of the thread most recently woke by this thread
            key.event_metadata = futex_get_wake_event_id(prev_pid);
        } else if (key.last_causal_event == LAST_OPERATION_IO) {
            key.event_metadata = get_curr_fd_thread(prev_pid);
            key.event_metadata_2 = fd_ids_get(key.event_metadata);
        }

//        clear_last_operation(prev_pid);

        key.store_stackTop = (prev_tc <= (total_count / STACK_FILTER) || prev_tc == 1) ? 1 : 0;
//        if (key.tid != key.tgid) { //If not parent thread
#ifdef SCHED_DEBUG
            bpf_trace_printk("Total count: %d\n", total_count);
            bpf_trace_printk("Dispatching stack trace for pid %d\n", prev_pid);
            bpf_trace_printk("Cause: %d\n", key.last_causal_event);
#endif
            gapp_crit_events.perf_submit(args, &key, sizeof(key));
//        }
    }

    //Next thread is a peer thread
    if (next) {
//        if (!is_doing_io(next_pid)) {
            tracking_thread_set_active(next_pid);
//        }

        u64 temp;
        //Get updated CM and store it to the CPU counter
        bpf_probe_read(&temp, sizeof(temp), ptr_globalCM);
        local_CM.update(&arrayKey, &temp);

        //Store switch in time
        inTS.update(&arrayKey, &newTS);

        //Store the local cumulative weighted thread count
        u64 temp_g_wt_threadCount;
        bpf_probe_read(&temp_g_wt_threadCount, sizeof(temp_g_wt_threadCount), g_wt_threadCount);
        LOCAL_WT_TC.update(&arrayKey, &temp_g_wt_threadCount);
    }
    return 0;
}
