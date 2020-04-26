//
// Created by Ashley Davies-Lyons on 2019-02-06.
//

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wall"
#pragma clang diagnostic ignored "-Wextra"
#include <linux/sched.h>
#include <linux/futex.h>
#include <linux/uio.h>
#pragma clang diagnostic pop

// Special hack to get around BPF limitations... These are resolved _before_ any code compilation or preprocessing.
// By some hacks in Python, which looks for the //DIRECT.
//
// Previously, I added a new directive #direct_import which Python looked for instead, but this confuses IDEs which
//   are then unable to index the files correctly.
//
// Reason for this:
//  As far as I understand, BPF function calls are translated into special bytecode _before_ the preprocessor runs.
//  As a result, #include-ing files with BPF in them means the BPF functions are cut and pasted in _after_ the
//    BPF compiler has already resolved the BPF functions, meaning they never get translated into the right bytecode
//    and end up throwing errors as they are referring to non-existent functions.
//  My understanding is this is because the functions like `bpf_trace_printk` are function calls in syntax only,
//    and really resolve to special bytecode -- not a real LLVM function call.
//  ¯\_(ツ)_/¯
#include "MGAPP/bpf_ide_helpers.h" //REMOVE
#include "MGAPP/fop.h" //DIRECT
#include "MGAPP/bpf_data.h" //DIRECT
#include "MGAPP/errors.h" //DIRECT
#include "MGAPP/thread_tracking.h" //DIRECT
#include "MGAPP/futex.h" //DIRECT
#include "MGAPP/io.h" //DIRECT
#include "MGAPP/scheduling.h" //DIRECT
#include "MGAPP/core.h" //DIRECT

// Return handler for syscall `clone`
int clone_ret(struct pt_regs *ctx) { FILTER
    tracking_track_thread(PT_REGS_RC(ctx));
    return 0;
}

int sched_switch(sched_switch_args *ctx) {
    // Has to be called as a tail call to avoid some BPF verifier limitations
    return core_sched_switch(ctx);
}

int sched_waking(sched_waking_args *ctx) {
    scheduling_sched_waking(ctx);
    return 0;
}

int sched_wakeup(sched_waking_args *ctx) {
    return core_sched_wakeup(ctx);
}

int sched_process_exit(sched_process_exit_args *ctx) {
    scheduling_sched_process_exit(ctx);
    return 0;
}
