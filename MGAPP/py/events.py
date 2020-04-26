import ctypes as ct


class FutexErrorEventT(ct.Structure):
    _fields_ = [
        ("error_code", ct.c_uint),
    ]


class SchedWakeFromFutexEventT(ct.Structure):
    _fields_ = [
        ("futex_addr", ct.c_voidp),
        ("pid", ct.c_uint),
        ("waking_pid", ct.c_uint),
        ("sleep_time", ct.c_ulonglong),
    ]


class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("tgid", ct.c_uint),
        ("cm", ct.c_ulonglong),
        ("source", ct.c_uint),
        ("user_stack_id", ct.c_int),
        ("store_stack_top", ct.c_int),
        ("last_causal_event", ct.c_int),
        ("event_metadata", ct.c_int),
        ("event_metadata_2", ct.c_int)]

class FutexWaitEventT(ct.Structure):
    _fields_ = [
        ("event_id", ct.c_uint),
        ("stack_id", ct.c_uint64),
        ("tgid", ct.c_uint),
        ("pid", ct.c_uint),
        ("futex_uaddr", ct.c_void_p),
    ]

class FutexWakeEventT(ct.Structure):
    _fields_ = [
        ("event_id", ct.c_uint),
        ("stack_id", ct.c_uint64),
        ("tgid", ct.c_uint),
        ("waking_pid", ct.c_uint),
        ("woken_pid", ct.c_uint),
        ("futex_uaddr", ct.c_void_p),
        ("sleep_time", ct.c_uint64),
    ]

# class OpenEventT(ct.Structure):
#     _fields_ = [
#         ("id", ct.c_uint),
#         ("fname", ct.strin)
#     ]
