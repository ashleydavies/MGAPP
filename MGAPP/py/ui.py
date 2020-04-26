import curses

from enum import Enum
from cmetric import *


class Pages(Enum):
    SUMMARY = 0
    ALL = 1
    SYNCHRONISATION = 2
    IO = 3
    LOCKS = 4


def output_line(window, w, skip_final_line=False):
    window.addstr("\n")
    for _ in range(w):
        window.addch(curses.ACS_HLINE)
    if not skip_final_line: window.addstr("\n")


def output_trace_collection(window, n, w, stack_trace, trace_collection, args):
    title_str = " Critical Path %d (Criticality Metric: %u):" % (n, trace_collection.criticality_metric())
    cause_str = "Cause: %s" % trace_collection.cause().name

    padding = w - len(cause_str) - len(title_str) - 1

    window.addstr(title_str)
    window.addstr(" " * padding)
    window.addstr(cause_str)
    output_line(window, w, skip_final_line=True)
    window.addstr("  %s\n" % stack_trace)

    if len(trace_collection.functions) > 0 or len(trace_collection.lines) > 0:
        output_line(window, w, skip_final_line=True)
        render_critical_funcs_and_lines(window,
                                        trace_collection.functions,
                                        trace_collection.lines)
    if args.causation_details:
        output_line(window, w)
        window.addstr(str(trace_collection.causes()))
        window.addstr("\n")


def render_menu(menu_win_internal, curr_page):
    menu_win_internal.clear()
    menu_win_internal.addstr(" ")
    for menu in list(Pages):
        color = 0
        if menu == curr_page:
            color = curses.color_pair(1)
        menu_win_internal.addstr(menu.name, color)

        if menu != list(Pages)[-1]:
            menu_win_internal.addstr(" | ")
    menu_win_internal.refresh()


def render_critical_funcs_and_lines(window, crit_funcs, crit_lines):
    sort_parm = {'key': lambda x: x[1], 'reverse': True}
    # TODO: Allow expansion to show more?
    for func, f_count in sorted(crit_funcs.items(), **sort_parm)[:4]:
        window.addstr("\n\t%s -- %u\n" % (func, f_count))

        for line, l_count in sorted(crit_lines[func].items(), **sort_parm)[:3]:
            window.addstr("\t\t%s -- %u\n" % (line, l_count))


def render_sync_trace_extra_details_closure(futex_events):
    def render_sync_trace_extra_details(window, w, entry, args):
        """
        :type entry: CMetricEntryCollection
        """
        # Sometimes we get stack traces mistakenly allocated to the wrong category.
        # There is what is pretty much a bug here -- some stack trace are vague and can be both wait or wake.
        # We should really be splitting these up instead of continuing to process them as one, but this shouldn't be too
        #  impactful most of the time.
        is_wait = len([entry for e in entry.entries if e.cause == SwitchCause.FUTEX_WAIT]) >= \
                  len([entry for e in entry.entries if e.cause == SwitchCause.FUTEX_WAKE])
        trace_tuple_id = 1 if is_wait else 0
        # Because we are listing the wakers for this wait
        output_word = "Waker" if is_wait else "Waking"
        keys = entry.synchronisation_keys()

        # Trace -> CMetric total
        results = dict()

        def same_trace(trace, key):
            return key in futex_events and futex_events[key][trace_tuple_id] == trace

        for key in set(keys):
            # window.addstr("%s\t" % str(key))
            if key not in futex_events or futex_events[key][trace_tuple_id] == "":
                continue

            trace = futex_events[key][trace_tuple_id]

            # results[trace] = sum([e.crit_metric for e in entry.entries if same_trace(trace, e.assoc_futex_key)])
            results[trace] = sum([1 for e in entry.entries if same_trace(trace, e.assoc_futex_key)])

        total = sum(results.values())

        if total == 0:
            return

        results = {k: ((100 * v) / total, v) for (k, v) in results.items()}

        for key, val in sorted(results.iteritems(), key=lambda item: item[1], reverse=True):
            output_line(window, w)
            # window.addstr("%s (Criticality: %d (%d%%)): \n\t%s\n" % (output_word, val[1], val[0], key))
            window.addstr(" %s (%d%%): \n %s\n" % (output_word, val[0], key))

    return render_sync_trace_extra_details


def render_io_trace_extra_details_closure(filenames):
    def render_io_trace_extra_details(window, w, entry, args):
        keys = entry.file_keys()
        results = dict()

        def same_file(file, key):
            return key in filenames and filenames[key] == file

        for key in keys:
            if key in filenames:
                if key not in filenames:
                    continue

                file = filenames[key]
                results[file] = sum([e.crit_metric for e in entry.entries if same_file(file, e.assoc_file_key)])

        if len(results) == 0:
            return

        output_line(window, w)

        window.addstr("Top files (with criticalities):\n\n")

        row_count = 0
        for k, v in sorted(results.iteritems(), key=lambda item: item[1], reverse=True):
            window.addstr("%s: %d\t\t" % (k, v))
            row_count = (row_count + 1) % 3
            if row_count == 0:
                window.addstr("\n")

        if row_count != 0:
            window.addstr("\n")

    return render_io_trace_extra_details


def output_lock(window, h, w, addr, traces, extra_traces):
    if len(traces) > 0:
        title_str = " Lock (uaddr %d) (Top criticality: %u):" % (addr, traces[0].crit_metric)
    else:
        title_str = " Lock (uaddr %d) (No associated criticality):" % (addr)

    window.addstr(title_str)

    if len(traces) > 0:
        output_line(window, w, skip_final_line=True)
        window.addstr(" Most critical unlockers:\n\n")
        trace_collections = []
        for stack_trace in set([trace.stack_trace for trace in traces]):
            trace_collections.append(
                (stack_trace, sum([trace.crit_metric for trace in traces if trace.stack_trace == stack_trace])))
        for (stack_trace, crit) in trace_collections:
            window.addstr("Criticality %d:\n\t%s\n" % (crit, stack_trace))

    if len(extra_traces) > 0:
        output_line(window, w, skip_final_line=True)

        window.addstr(" Unlockers with no criticality (no particular order):\n\n")
        for extra_trace in extra_traces:
            window.addstr("%s\n\n" % extra_trace)


def render_locks(w, window, lock_traces):
    if len(lock_traces) == 0:
        err_window = window.derwin(3, w, 1, 0)
        err_window.border()
        err_window.addstr(1, 1, " No critical lock details were recorded.")
        return 3

    n = 1
    window_pos = 0
    inner_width = w - 2
    for addr, (traces, extra_traces) in sorted(lock_traces.items(),
                                               key=lambda k: k[1][0][0].crit_metric if len(k[1][0]) > 0 else 0,
                                               reverse=True)[:10]:
        text_size_window = curses.newpad(250, inner_width)
        output_lock(text_size_window, n, inner_width, addr, traces, extra_traces)

        (window_height_inner, _) = text_size_window.getyx()

        trace_window = window.derwin(window_height_inner + 3, w, window_pos, 0)
        trace_window.border()
        internal_window = trace_window.derwin(window_height_inner + 1, inner_width, 1, 1)
        output_lock(internal_window, n, inner_width, addr, traces, extra_traces)
        window_pos += window_height_inner + 3
        n += 1

    return window_pos


# Extra detail callback allows polymorphic-style addition of information where it is known that it will be known
def render_traces(w, window, traces, args, extra_detail_callback=lambda window, w, entry, args: ""):
    if len(traces) == 0:
        err_window = window.derwin(3, w, 1, 0)
        err_window.border()
        err_window.addstr(1, 1, " No bottlenecks of this type were recorded.")
        return 3

    n = 1
    window_pos = 0
    inner_width = w - 2
    for stack_trace, entry in sorted(traces.items(), key=lambda k: k[1].criticality_metric(), reverse=True)[:10]:
        text_size_window = curses.newpad(1000, inner_width)
        output_trace_collection(text_size_window, n, inner_width, stack_trace, entry, args)
        extra_detail_callback(text_size_window, inner_width, entry, args)

        (window_height_inner, _) = text_size_window.getyx()

        trace_window = window.derwin(window_height_inner + 3, w, window_pos, 0)
        trace_window.border()
        internal_window = trace_window.derwin(window_height_inner + 1, inner_width, 1, 1)
        output_trace_collection(internal_window, n, inner_width, stack_trace, entry, args)
        extra_detail_callback(internal_window, inner_width, entry, args)
        window_pos += window_height_inner + 3
        n += 1

    return window_pos


def render_summary_text(window, w, thread_cm, total_switch, cmetric_reports, post_time, futex_events, filenames):
    """
    :type cmetric_reports: list[CMetricEntry]
    """
    window.addstr("%d threads were discovered and tracked.\n" % len(thread_cm))
    output_line(window, w)

    window.addstr("Criticality Metric per thread:\n")

    cm_sum = 0
    thread_display_count = 8
    for thread, cm in sorted(thread_cm.items(), key=lambda x: x[1].value, reverse=True)[:thread_display_count]:
        window.addstr(" %10u: %u\n" % (thread.value, cm.value))
        cm_sum += cm.value

    if len(thread_cm) > thread_display_count:
        window.addstr(" ... and %d more." % (len(thread_cm) - thread_display_count))

    window.addstr("\nTotal: %d\n" % cm_sum)

    output_line(window, w)

    window.addstr("Total switches: %u\n" % total_switch)
    window.addstr("Critical switches: %u\n" % len(cmetric_reports))
    window.addstr("Post Processing time (ms): %u\n" % int(post_time.total_seconds() * 1000))

    if len(CMetricEntryCollection.all_critical_lines) > 0 or len(CMetricEntryCollection.all_critical_functions) > 0:
        output_line(window, w)
        window.addstr("Top critical functions and lines, with frequency:\n")

        render_critical_funcs_and_lines(window,
                                        CMetricEntryCollection.all_critical_functions,
                                        CMetricEntryCollection.all_critical_lines)

    wake_traces = sorted([report for report in cmetric_reports if report.cause == SwitchCause.FUTEX_WAKE],
                         key=lambda x: x.crit_metric, reverse=True)[:5]

    if len(wake_traces) > 0:
        output_line(window, w)

        window.addstr("Most critical futex wakes:\n\n")

        for trace in wake_traces:
            window.addstr("Criticality %d:\n" % trace.crit_metric)
            window.addstr("    %s\n\n" % trace.stack_trace)

    # These results are too varied to provide much guaranteed utility
    # wait_wake_events = sorted([(report.crit_metric, futex_events[report.assoc_futex_key][0])
    #                     for report in cmetric_reports
    #                     if report.cause == SwitchCause.FUTEX_WAIT and report.assoc_futex_key in futex_events
    #                     and futex_events[report.assoc_futex_key][0] != ""][:5],
    #                           key=lambda (c, _): c, reverse=True)
    # wait_wake_traces = set([s for (_, s) in wait_wake_events])
    # wait_wake_events = sorted([(sum([c for (c, s) in wait_wake_events if s == strace]), strace) for strace in wait_wake_traces],
    #                          key=lambda (c, _): c, reverse=True)

    # if len(wait_wake_events) > 0:
    #     output_line(window, w)
    #
    #     window.addstr("Wakers of most critical futex waits:\n\n")
    #
    #     for (crit, trace) in wait_wake_events:
    #         window.addstr("Criticality %d:\n" % crit)
    #         window.addstr("    %s\n\n" % trace)

    file_traces = sorted([report for report in cmetric_reports if report.cause == SwitchCause.IO],
                         key=lambda x: x.crit_metric, reverse=True)[:5]
    if len(file_traces) > 0:
        output_line(window, w)

        window.addstr("Most critical file activities:\n\n")

        for trace in file_traces:
            window.addstr("Criticality %d:\n" % trace.crit_metric)
            file_key = trace.assoc_file_key
            if file_key in filenames:
                window.addstr("File name: %s\n" % filenames[file_key])
            else:
                window.addstr("File name unknown.\n")
            window.addstr("    %s\n\n" % trace.stack_trace)


def render_summary(outer_window, h, w, thread_cm, total_switch, cmetric_reports, post_time, futex_events, filenames):
    text_size_window = curses.newpad(5000, w - 4)
    render_summary_text(text_size_window, w - 4, thread_cm, total_switch, cmetric_reports, post_time, futex_events,
                        filenames)
    (window_height_inner, _) = text_size_window.getyx()
    window_height_inner += 1

    border_window = outer_window.derwin(window_height_inner + 4, w, 0, 0)
    border_window.border()

    window = border_window.derwin(window_height_inner, w - 4, 2, 2)
    render_summary_text(window, w - 4, thread_cm, total_switch, cmetric_reports, post_time, futex_events, filenames)

    return window_height_inner + 4
