from enum import IntEnum
import argparse
import subprocess


def list_to_freq_dict(dict_arg):
    return {entry: dict_arg.count(entry) for entry in set(dict_arg)}


def addr2line(element, path):
    if (element, path) not in addr2line.cache:
        addr2line.cache[(element, path)] = str(
            subprocess.check_output(
                ['addr2line', '-s', '-C', '-f', '-p', '-i', "0x" + element, '-e', path],
                stderr=subprocess.STDOUT)
        ).strip("\n ' '")

    return addr2line.cache[(element, path)]


def get_addr_symbol(addr, bpf, tgid):
    if addr not in get_addr_symbol.symbol_cache:
        get_addr_symbol.symbol_cache[addr] = bpf.sym(addr, tgid, show_offset=True, show_module=True)

    return get_addr_symbol.symbol_cache[addr]


def positive_int(val):
    try:
        ival = int(val)
    except ValueError:
        raise argparse.ArgumentTypeError("must be an integer")

    if ival < 0:
        raise argparse.ArgumentTypeError("must be positive")
    return ival


class SwitchCause(IntEnum):
    UNKNOWN = 0
    FUTEX_WAIT = 1
    FUTEX_WAKE = 2
    IO = 3


class BottleneckCause(IntEnum):
    UNKNOWN = 0
    SYNCHRONISATION = 1
    IO = 2


ERROR_LOOKUP = {1: "Unknown Futex operation", 2: "Unexpected futex_wait (already waiting)",
                3: "Unexpected futex_wake (already waking)",
                4: "Waker of a thread which was waiting on a futex was not recorded",
                5: "A new thread was discovered which was not previously being tracked; this is a *warning* if output against an existing PID, and an *error* if it happens with a PID which this script started",
                6: "The futex return probe triggered without the call probe triggering. If this error flags from a program which this tool *started*, something has gone seriously wrong",
                7: "Unable to access known array location",
                8: "Unusual behaviour in openat: A call to openat from this thread was already ongoing?",
                9: "Unusual behaviour in openatret: No call was recorded?"}


