Some plain text to stop compilation if this file is accidentally included

/*
int kprobe__try_to_wake_up(struct pt_regs *ctx, struct task_struct *p) { FILTER
    int zero = 0;
    if (!relevant_pid(p->pid)) return 0;
    bpf_trace_printk("TRYING TO WAKE UP %u\n", p->pid);
    curr_wake_up_calls.insert(&pid, &zero);
    return 0;
}

int kretprobe__try_to_wake_up(struct pt_regs *ctx) { FILTER
    if (curr_wake_up_calls.lookup(&pid) == NULL) return 0;
    curr_wake_up_calls.delete(&pid);
    bpf_trace_printk("WAKE UP STATUS: %d\n", PT_REGS_RC(ctx));
    return 0;
}*/

/*
 *
 * WITHIN SCHED_SWITCH
 *
 *
    if (!relevant_pid(args->prev_pid)) {
        bpf_trace_printk("Switching in thread %d\n", args->next_pid);
    } else if (!relevant_pid(args->prev_pid)) {
        bpf_trace_printk("Switching out thread %d\n", args->prev_pid);
    } else {
        bpf_trace_printk("Switching from thread %d to \n", args->prev_pid);
        bpf_trace_printk("%d\n", args->next_pid);
    }
    if ((args->prev_state & TASK_RUNNING) != 0)
        bpf_trace_printk("Prev state == TASK_RUNNING\n");
    if ((args->prev_state & TASK_INTERRUPTIBLE) != 0)
        bpf_trace_printk("Prev state == TASK_INTERRUPTIBLE\n");
    if ((args->prev_state & TASK_UNINTERRUPTIBLE) != 0)
        bpf_trace_printk("Prev state == TASK_UNINTERRUPTIBLE\n");
    if ((args->prev_state & TASK_STOPPED) != 0)
        bpf_trace_printk("Prev state == TASK_STOPPED\n");
    if ((args->prev_state & EXIT_ZOMBIE) != 0)
        bpf_trace_printk("Prev state == EXIT_ZOMBIE\n");
    if ((args->prev_state & (TASK_STOPPED | EXIT_ZOMBIE)) != 0) {
        bpf_trace_printk("TASK EXITED\n");
    }*/
