#! /usr/bin/env python

import os
import argparse
import ctypes as ct
import sys
import datetime
import subprocess
import curses
import re
import socket
import struct
import pprint
from subprocess import Popen
from enum import Enum, IntEnum

from bcc import ArgString, BPF, PerfType, PerfSWConfig

from MGAPP.py.bpf_load import *
from MGAPP.py.cmetric import *
from MGAPP.py.events import *
from MGAPP.py.filter import *
from MGAPP.py.ui import *
from MGAPP.py.util import *


#####
# Argument Parsing
#####


def parse_args():
    parser = argparse.ArgumentParser(description="Generates stack traces for critical code sections")
    subparsers = parser.add_subparsers()

    # Program identification options
    name_parser = subparsers.add_parser("path")
    name_parser.add_argument(metavar="<Executable path>", dest="path",
                             help="Path of the executable file to be profiled")
    name_parser.add_argument("-s", dest="spawn", action='store_true',
                             help="If set, spawns a process and tracks it rather than tracing any process of the same "
                                  "name")
    name_parser.set_defaults(func=init_bpf_path)
    name_parser.add_argument('cmd_args', nargs=argparse.REMAINDER)

    pid_parser = subparsers.add_parser("pid")
    pid_parser.add_argument(metavar="<Pid>", dest="pid", help="Pid of the executable to be profiled")
    pid_parser.set_defaults(func=init_bpf_pid)

    # Meta options
    parser.add_argument("-v", dest="verbose_trace", action='store_true',
                        help="Enables trace printing for debugging purposes")

    # Tracing options
    parser.add_argument("-c", dest="causation_details", action='store_true',
                        help="If set, prints additional information about stack traces causes.")
    parser.add_argument("-t", metavar="<Threshold>", dest="threshold", type=positive_int, default=2,
                        help="Ratio of total threads to active threads to trigger stack trace. Default = 2")
    parser.add_argument("-f", metavar="<Sampling Frequency>", dest="sample_freq", type=positive_int, required=False,
                        default=333, help="Sampling frequency in Hz. Default = 333Hz (equivalent to 3 ms)")
    parser.add_argument("-d", metavar="<Stack Depth>", dest="stack_depth", type=positive_int, required=False,
                        default=10, help="Maximum Stack depth for stack unwinding. Default = 10")
    parser.add_argument("-b", metavar="<Ring buffer Size>", dest="ring_buffer_size", type=positive_int, required=False,
                        default=64, help="Number of pages to be allocated for the ring buffer, Default = 64")
    parser.add_argument("-e", dest="enhanced_stack_traces", action='store_true', required=False,
                        help="Uses addr2line to attempt to add line number details to stack traces, and replaces common"
                             " patterns like C++ thread initialisation with a compact form")

    args = parser.parse_args()
    return args


total_switch = 0


def main():
    global total_switch

    args = parse_args()
    bpf_prog = load_bpf_prog(args)
    bpf_prog, continue_polling_func = args.func(args, bpf_prog)

    # noinspection PyBroadException
    try:
        b = BPF(text=bpf_prog)
    except Exception:
        print("Failed to compile BPF")
        sys.exit(1)

    attach_bpf_probes(b, args.sample_freq)

    cmetric_reports = list()  # type: list[CMetricEntry]
    sample_addresses = dict()  # Stores addresses corresponding to samples

    stack_traces = b["stacktraces"]
    futex_stack_traces = b["futex_stack_traces"]
    thread_cm = b.get_table("CM_hash")
    program_name = os.path.basename(args.path)

    # noinspection PyUnusedLocal
    # def print_futex_wait_event(cpu, data, size):
    #     event = ct.cast(data, ct.POINTER(FutexWaitEventT)).contents
    #     # print(event.stack_id)
    #     # print(event.pid)
    #     for addr in futex_wait_stack_traces.walk(event.stack_id):
    #         sym = b.sym(addr, event.pid, show_offset=True, show_module=True)
    #         print("\tFUTEX: %s" % sym)

    # noinspection PyUnusedLocal
    def print_error_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(FutexErrorEventT)).contents
        print("Error/warning from eBPF: %s (Error %d)" % (
            ERROR_LOOKUP[event.error_code] if event.error_code in ERROR_LOOKUP else "UNKNOWN ERROR", event.error_code))

    # noinspection PyUnusedLocal
    # def print_sched_wake_from_futex_event(cpu, data, size):
    #     event = ct.cast(data, ct.POINTER(SchedWakeFromFutexEventT)).contents
    #     sleepTime = event.sleep_time / 1000000000.0
    #     if event.waking_pid == 0:
    #         print("A thread %d was woken from timeout on a futex %02x, after %.9fs\n" %
    #               (event.pid, event.futex_addr, sleepTime))
    #     else:
    #         print("A thread %d was woken by thread %d from a futex %02x, after %.9fs\n" %
    #               (event.pid, event.waking_pid, event.futex_addr, sleepTime))

    # noinspection PyUnusedLocal
    def print_event(cpu, data, size):
        global total_switch

        event = ct.cast(data, ct.POINTER(Data)).contents

        if event.source == 0:  # Sample data
            addr_symbol = get_addr_symbol(event.user_stack_id, b, event.tgid)

            if addr_symbol == "[unknown]":
                return

            # if program_name in addr_symbol:  # If address belongs to application address map
            # Add to list of samples for this thread ID
            if event.pid not in sample_addresses:
                sample_addresses[event.pid] = list()

            sample_addresses[event.pid].append(format(event.user_stack_id, 'x'))
            return

        # Handle switching events
        total_switch += 1

        if event.source == 1:  # Critical Stack trace
            user_stack = [] if event.user_stack_id < 0 else \
                stack_traces.walk(event.user_stack_id)
            # For each address in the stack trace, get the symbols and create call path
            call_path, flag = process_stack_trace(user_stack, event.tgid, event.pid, event.store_stack_top)
            # print("Processed stack trace ! " + call_path + " " + str(event.pid))
            if flag > 0:
                entry = CMetricEntry(event.cm, call_path, set(sample_addresses[event.pid]), event.last_causal_event)

                if event.event_metadata != 0:
                    entry.set_assoc_futex_key((event.pid, event.event_metadata))
                if event.last_causal_event == SwitchCause.IO:
                    entry.set_assoc_file_key((event.event_metadata, event.event_metadata_2))
                    # print("IO on %d,%d" % (event.event_metadata, event.event_metadata_2))
                    # if filenames.has_key((event.event_metadata, event.event_metadata_2)):
                    #    print("filename: %s" % filenames[(event.event_metadata, event.event_metadata_2)])

                cmetric_reports.append(entry)

        # event.source == 2 just needs a reset of the sample addresses (non-critical stack report)
        sample_addresses[event.pid] = []

    def process_stack_trace(user_stack_list, tgid, pid, store_stack_top):
        replace_patterns = [
            (["void std::__invoke_impl<void, void (*)(int), int>(std::__invoke_other, void (*&&)(int), int&&)",
              "std::__invoke_result<void (*)(int), int>::type std::__invoke<void (*)(int), int>(void (*&&)(int), int&&)",
              "decltype (__invoke((_S_declval<0ul>)(), (_S_declval<1ul>)())) std::thread::_Invoker<std::tuple<void ("
              "*)(int), int> >::_M_invoke<0ul, 1ul>(std::_Index_tuple<0ul, 1ul>)",
              "std::thread::_Invoker<std::tuple<void (*)(int), int> >::operator()()",
              "std::thread::_State_impl<std::thread::_Invoker<std::tuple<void (*)(int), int> > >::_M_run()"],
             "C++ Thread Initialisation"),
            (["std::__invoke_result<void (*)(",
              "decltype (__invoke((_S_declval<0ul>)(), (_S_declval<1ul>)()",
              "std::thread::_Invoker<std::tuple<void (*)(",
              "std::thread::_State_impl<std::thread::_Invoker<std::tuple<void (*)("],
             "C++ Thread Initialisation"),
            (["void std::__invoke_impl<",
              "std::__invoke_result<void (*)(int), int>::type std::__invoke<void (*)(int)",
              "decltype (__invoke((_S_declval<0ul>)(), (_S_declval<1ul>)()))",
              "std::thread::_Invoker<std::tuple<"
              "std::thread::_State_impl<std::thread::_Invoker<"
              ],
             "C++ Thread Initialisation"),
            (["tbb::internal::parallel_for_body<main::{lambda(unsigned int)#1}, unsigned",
              "tbb::interface9::internal::start_for<tbb::blocked_range<unsigned int>, tbb",
              "void tbb::interface9::internal::balancing_partition_type<tbb::interface9::",
              "void tbb::interface9::internal::partition_type_base<tbb::interface9::inter",
              "tbb::interface9::internal::start_for<tbb::blocked_range<unsigned int>, tbb",
              "tbb::interface9::internal::start_for<tbb::blocked_range<unsigned int>, tbb"], "TBB Parallel For")
        ]

        depth = 0
        stack_lines = []
        for addr in user_stack_list:
            addr_symbol = get_addr_symbol(addr, b, tgid)

            if addr_symbol.startswith("[unknown]"):
                continue

            # if program_name in addr_symbol:  # If address belongs to application address map

            line_add = ""
            if depth == 0:  # Store top address of stack trace
                if pid not in sample_addresses:
                    sample_addresses[pid] = list()
                if len(sample_addresses[pid]) == 0 and store_stack_top == 1:
                    sample_addresses[pid].append(format(addr, 'x'))
                line_add = addr_symbol.split('+', 1)[0].strip("\n ' '")
            else:  # If not stack top address
                line_add = addr_symbol.split('+', 1)[0].strip("\n ' '")

            if args.enhanced_stack_traces:
                # if addr_symbol.endswith("[%s]" % os.path.basename(args.path)):
                addr2line_out = addr2line(hex(addr).rstrip("L").lstrip("0x") or "0", args.path)
                if addr2line_out.startswith("??"):
                    stack_lines.append(line_add)
                else:
                    addr2line_out = re.sub(" \(discriminator \d+\)", "", addr2line_out)
                    stack_lines.append(addr2line_out)
            else:
                stack_lines.append(line_add)

            depth += 1

            if depth == args.stack_depth:  # Number of stack frames
                break

        if args.enhanced_stack_traces:
            for (pattern, replacement) in replace_patterns:
                for start_idx in range(len(stack_lines)):
                    # May happen after replacements
                    if start_idx >= len(stack_lines):
                        break

                    idx = 0
                    while idx < len(pattern) and stack_lines[start_idx + idx].startswith(pattern[idx]):
                        idx += 1
                        if start_idx + idx >= len(stack_lines):
                            break
                    if idx == len(pattern):
                        del stack_lines[start_idx:start_idx + idx - 1]
                        stack_lines[start_idx] = "<< %s >>" % replacement

        call_path = "\n\t<--- ".join(stack_lines)

        # Hacky, but this patches over a glitch(??) where start_thread gets given huge criticality
        if call_path == "start_thread":
            return "", 0

        return call_path, depth

    futex_events = dict()  # type: dict[(int, int): (str, str, int)]
    filenames = dict()  # type: dict[(int, int): str]

    def futex_event_init_if_not_exist(key, uaddr):
        if key in futex_events:
            return
        futex_events[key] = ("", "", uaddr)

    def futex_wait_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(FutexWaitEventT)).contents
        (trace, depth) = process_stack_trace(futex_stack_traces.walk(event.stack_id), event.tgid, event.pid, 1)
        fe_key = (event.pid, event.event_id)
        futex_event_init_if_not_exist(fe_key, event.futex_uaddr)
        futex_events[fe_key] = (trace, futex_events[fe_key][1], futex_events[fe_key][2])

    def futex_wake_event(cpu, data, size):
        event = ct.cast(data, ct.POINTER(FutexWakeEventT)).contents
        (trace, depth) = process_stack_trace(futex_stack_traces.walk(event.stack_id), event.tgid, event.waking_pid, 1)
        fe_key = (event.woken_pid, event.event_id)
        futex_event_init_if_not_exist(fe_key, event.futex_uaddr)
        futex_events[fe_key] = (futex_events[fe_key][0], trace, futex_events[fe_key][2])

    def open_event(cpu, data, size):
        event = b["open_events"].event(data)
        filenames[(event.fd, event.fd_id)] = event.fname
        # print("Event fname: %s fd %d fd_id %d" % (event.fname, event.fd, event.fd_id))

    def connect_event(cpu, data, size):
        event = b["connect_events"].event(data)
        ip_addr_str = socket.inet_ntoa(struct.pack('I', event.ip_addr))
        # print("%s = %s" % (str((event.sock_fd, event.fd_id)), ip_addr_str))
        filenames[(event.sock_fd, event.fd_id)] = ip_addr_str

    b["error_events"].open_perf_buffer(print_error_event)
    b["gapp_crit_events"].open_perf_buffer(print_event, page_cnt=args.ring_buffer_size)

    b["futex_wait_events"].open_perf_buffer(futex_wait_event)
    b["futex_wake_events"].open_perf_buffer(futex_wake_event)
    b["open_events"].open_perf_buffer(open_event)
    b["connect_events"].open_perf_buffer(connect_event)

    if args.verbose_trace:
        b.trace_print()

    try:
        while 1:
            b.perf_buffer_poll(timeout=100)
            if not continue_polling_func():
                break
    except KeyboardInterrupt:
        pass

    event_issues = 0
    for (t1, t2, _) in futex_events.values():
        if t1 == "" or t2 == "":
            event_issues += 1

    print("Total futex events: %d, error events: %d" % (len(futex_events), event_issues))

    # Post Processing the stack traces
    postproc_start_time = datetime.datetime.now()

    crit_stack_trace_collections = dict()  # type: dict[string, CMetricEntryCollection]

    merge_cmetric_entries(cmetric_reports, crit_stack_trace_collections)
    postprocess(crit_stack_trace_collections, args)

    # Futex post-processing

    futex_addresses = set([addr for (_, _, addr) in futex_events.values()])
    faddr_to_traces = {
        addr: [(wait, wake, key) for (key, (wait, wake, address)) in futex_events.iteritems() if address == addr]
        for addr in futex_addresses}

    crit_faddr_traces = {}
    for addr, entry_list in faddr_to_traces.iteritems():
        crit_faddr_traces[addr] = ([], [])
        wake_list = set([wake for (_, wake, _) in entry_list])

        matching_cmetric_reports = [report for report in cmetric_reports if report.stack_trace == wake]
        for entry in matching_cmetric_reports:
            crit_faddr_traces[addr][0].append(entry)
        for entry in set([e[1] for e in entry_list]):
            if entry not in set([report.stack_trace for report in matching_cmetric_reports]) and entry != "":
                crit_faddr_traces[addr][1].append(entry)

        # for (wait, wake, key) in entry_list:
        #     # TODO: This can be reduced from O(nm) to O(n + mlogm) with a sort and linear search on the cmetric_reports
        #     matching_cmetric_reports = [report for report in cmetric_reports if report.stack_trace == wake]
        #     if len(matching_cmetric_reports) == 0:
        #         continue
        #
        #     print("Matching report!")
        #     for entry in matching_cmetric_reports:
        #         if entry.cause == SwitchCause.FUTEX_WAKE:
        #             crit_faddr_traces[addr].append(entry)
        #
        crit_faddr_traces[addr] = (sorted(crit_faddr_traces[addr][0], key=lambda e: e.crit_metric, reverse=True),
                                   crit_faddr_traces[addr][1])

        if len(crit_faddr_traces[addr][0]) == 0 and len(crit_faddr_traces[addr][1]) == 0:
            del crit_faddr_traces[addr]

    postproc_end_time = datetime.datetime.now()
    post_time = postproc_end_time - postproc_start_time

    def output_summary(outer_window, h, w):
        return render_summary(outer_window, h, w, thread_cm, total_switch, cmetric_reports, post_time, futex_events,
                              filenames)

    def output_all_traces(window, h, w):
        return render_traces(w, window, crit_stack_trace_collections, args)

    def output_sync_traces(window, h, w):
        traces = {k: v for k, v in crit_stack_trace_collections.iteritems()
                  if any(cause in v.causes() for cause in [SwitchCause.FUTEX_WAIT, SwitchCause.FUTEX_WAKE])}
        return render_traces(w, window, traces, args, render_sync_trace_extra_details_closure(futex_events))

    def output_io_traces(window, h, w):
        traces = {k: v for k, v in crit_stack_trace_collections.iteritems()
                  if any(cause in v.causes().keys() for cause in [SwitchCause.IO])}
        return render_traces(w, window, traces, args, render_io_trace_extra_details_closure(filenames))

    def output_locks(window, h, w):
        return render_locks(w, window, crit_faddr_traces)

    output_funcs = {Pages.SUMMARY: output_summary, Pages.ALL: output_all_traces,
                    Pages.IO: output_io_traces, Pages.SYNCHRONISATION: output_sync_traces,
                    Pages.LOCKS: output_locks}

    def output(stdscr, curr_page):
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.curs_set(0)
        stdscr.clear()

        height, width = stdscr.getmaxyx()
        stdscr.resize(6, width)

        title_win = stdscr.derwin(3, width, 0, 0)
        title_win.border()
        title_win.addstr(1, 1, " GAPP Results | %s | 'q' to quit" % args.path, curses.A_BOLD)

        menu_win = stdscr.derwin(3, width, 3, 0)
        menu_win.border()
        menu_win_internal = menu_win.derwin(1, width - 2, 1, 1)

        # TODO: 10000 may not be enough height... Can we make it dynamic?
        main_win = curses.newpad(10000, width)

        scroll_pos = 0
        page_height = output_funcs[curr_page](main_win, height - 6, width)

        while True:
            page_height = output_funcs[curr_page](main_win, height - 6, width)
            render_menu(menu_win_internal, curr_page)
            main_win.refresh(scroll_pos, 0, 6, 0, height - 1, width)

            char = stdscr.getch()
            term = char == ord('q')
            menu_change = 0
            if char == curses.KEY_LEFT:
                menu_change = -1
            if char == curses.KEY_RIGHT:
                menu_change = 1
            if menu_change != 0:
                scroll_pos = 0

            scroll_pos_delta = 0
            if char == curses.KEY_DOWN:
                scroll_pos_delta = 1
            if char == curses.KEY_UP:
                scroll_pos_delta = -1
            if char == ord('j'):
                scroll_pos_delta = 5
            if char == ord('k'):
                scroll_pos_delta = -5

            scroll_pos = max(0, scroll_pos + scroll_pos_delta)
            scroll_pos = min(scroll_pos, page_height - height + 6)

            if menu_change != 0:
                next_page = curr_page.value + menu_change
                curr_page = list(Pages)[next_page % len(Pages)]
                main_win.clear()
                page_height = output_funcs[curr_page](main_win, height - 6, width)

            if term:
                break

    curses.wrapper(output, Pages.SUMMARY)
    sys.exit()


if __name__ == '__main__':
    main()
