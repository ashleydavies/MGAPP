import os
from subprocess import Popen

from bcc import PerfType, PerfSWConfig
from filter import *

#####
# BPF Program Loading
#####


def load_bpf_prog(args):
    with open('mgapp.c', 'r') as f:
        bpf_prog = f.read()

    bpf_prog = prepreprocess(bpf_prog)
    bpf_prog = bpf_prog.replace('STACK_FILTER', str(args.threshold))
    bpf_prog = bpf_prog.replace('FILTER', FILTER_CODE)

    return bpf_prog


INCLUDE_PREFIX = '#include "'
DIRECT_INCLUDE_SUFFIX = '" //DIRECT'
REMOVE_INCLUDE_SUFFIX = '" //REMOVE'


# See comment in main C file header section for more info
def process_direct_include(line):
    # "#direct_include ..." 16 characters to skip
    if not line.startswith(INCLUDE_PREFIX):
        return line

    if line.endswith(REMOVE_INCLUDE_SUFFIX):
        # print("Neglecting import of " + line[len(INCLUDE_PREFIX):-len(REMOVE_INCLUDE_SUFFIX)] + " due to REMOVE "
        return ""

    if not line.endswith(DIRECT_INCLUDE_SUFFIX):
        return line

    line = line[len(INCLUDE_PREFIX):-len(DIRECT_INCLUDE_SUFFIX)]
    # print("Pre-compilation import of " + line)

    with open(line, 'r') as f:
        content = f.read()
    content = "#line 1 \"" + line + "\"\n" + content
    return prepreprocess(content)


def prepreprocess(bpf_prog):
    lines = bpf_prog.splitlines()
    return "\n".join(map(process_direct_include, lines))


def attach_bpf_probes(b, sample_freq):
    # TODO: attach_kprobe is not working correctly; it won't detect the x64 prefix for some reason
    # b.attach_kprobe(event=b.get_syscall_fnname("futex"), fn_name="futex_call")
    # b.attach_kretprobe(event=b.get_syscall_fnname("futex"), fn_name="futex_ret")
    b.attach_kretprobe(event=b.get_syscall_fnname("clone"), fn_name="clone_ret")
    b.attach_tracepoint(tp="sched:sched_switch", fn_name="sched_switch")
    b.attach_tracepoint(tp="sched:sched_waking", fn_name="sched_waking")
    b.attach_tracepoint(tp="sched:sched_wakeup", fn_name="sched_wakeup")
    b.attach_tracepoint(tp="sched:sched_process_exit", fn_name="sched_process_exit")
    b.attach_tracepoint(tp="syscalls:sys_exit_read", fn_name="read_exit_probe")

    # b.attach_uprobe(name="c", sym="fclose", fn_name="probe_close")
    # b.attach_uretprobe(name="c", sym="fclose", fn_name="retprobe_close")

    b.attach_uprobe(name="c", sym="_IO_new_file_close_it", fn_name="glibc_file_close")
    #b.attach_uretprobe(name="c", sym="_IO_new_file_close_it", fn_name="aretprobe_close")

    #b.attach_uprobe(name="c", sym="_IO_un_link", fn_name="bprobe_close")
    b.attach_uretprobe(name="c", sym="_IO_un_link", fn_name="glibc_file_close_ret")

    b.attach_perf_event(ev_type=PerfType.SOFTWARE,
                        ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
                        sample_freq=sample_freq)


# TODO: Tidy duplication of initialisation logic
def init_bpf_path(args, bpf_prog):
    if args.spawn:
        process = Popen(["bin/bootstrap", args.path] + args.cmd_args)
        return init_bpf_pid_base(args, process.pid, bpf_prog), lambda: (process.poll() or process.returncode is None)

    print("Waiting for process to run... Ctrl+C to terminate...")
    bpf_prog = "\n".join(["#define PROG_COMM \"{name}\"".format(name=os.path.basename(args.path)), bpf_prog])
    return bpf_prog, lambda: True


def init_bpf_pid(args, bpf_prog):
    return init_bpf_pid_base(args, args.pid, bpf_prog), lambda: True


def init_bpf_pid_base(args, pid, bpf_prog):
    print("PID: {}".format(pid))
    bpf_prog = "\n".join(["#define PROG_PID " + str(pid), bpf_prog])

    return bpf_prog