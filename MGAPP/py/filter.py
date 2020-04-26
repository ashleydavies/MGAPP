FILTER_CODE = "u64 pidtgid = bpf_get_current_pid_tgid();" + \
              "u32 tgid = pidtgid >> 32;" + \
              "u32 pid = pidtgid;" + \
              "char comm[TASK_COMM_LEN];" + \
              "bpf_get_current_comm(&comm, sizeof(comm));" + \
              "if (!tracking_thread_should_be_tracked(pid, tgid, comm)) return 0;" + \
              "/* Start tracking the thread if we weren't already tracking it */ " + \
              "if (!tracking_thread_is_tracked(pid)) {{" + \
              "  ERROR_NEW_THREAD_DISCOVERED_TRACKING;" + \
              "  tracking_track_thread(pid);" + \
              "}}"
