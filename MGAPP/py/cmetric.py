from util import *


class CMetricEntry:
    def __init__(self, crit_metric, stack_trace, sample_addresses, cause):
        """
        :type crit_metric: int
        :type stack_trace: string
        :type sample_addresses: set[str]
        :type cause: int
        """
        self.crit_metric = crit_metric
        self.stack_trace = stack_trace
        self.sample_addresses = sample_addresses
        self.cause = SwitchCause(cause)
        self.assoc_futex_key = ""
        self.assoc_file_key = ""

    def set_assoc_futex_key(self, key):
        self.assoc_futex_key = key

    def set_assoc_file_key(self, key):
        self.assoc_file_key = key


class CMetricEntryCollection:
    all_critical_functions = dict()
    all_critical_lines = dict()

    def __init__(self):
        self.entries = list()  # type: List[CMetricEntry]
        self.functions = dict()
        self.lines = dict()

    def add(self, entry):
        self.entries.append(entry)

    def criticality_metric(self):
        return sum([entry.crit_metric for entry in self.entries])

    # Frequency dictionary of all sample addresses
    def sample_addrs(self):
        all_addrs = [addr for entry in self.entries for addr in entry.sample_addresses]
        return list_to_freq_dict(all_addrs)

    # Post-processing step for combining address samples
    def combine_samples(self, args):
        def add_function_and_line(functions_dict, lines_dict, function, line):
            if function not in functions_dict:
                functions_dict[function] = 0
                lines_dict[function] = dict()

            if line not in lines_dict[function]:
                lines_dict[function][line] = 0

            functions_dict[function] += count
            lines_dict[function][line] += count

        for element, count in self.sample_addrs().items():
            # Map address to function name and line of code
            result = addr2line(element, args.path)

            if not result or " at " not in result:
                continue

            # Format: "std::mutex::lock() at std_mutex.h:103"
            result = result.split('\n', 1)[0].strip("\n '")

            function, line = result.split(" at ", 1)[0:2]
            function, line = function.strip(), line.strip()

            if line:
                line = line.split(" (", 1)[0]

            add_function_and_line(self.functions, self.lines, function, line)
            # all_X are static, used as accumulators between all(!) metrics to present as a summary
            add_function_and_line(CMetricEntryCollection.all_critical_functions,
                                  CMetricEntryCollection.all_critical_lines,
                                  function, line)

    def causes(self):
        all_causes = [entry.cause for entry in self.entries]
        return list_to_freq_dict(all_causes)

    def cause(self):
        all_causes = set(self.causes().keys()) - {SwitchCause.UNKNOWN}
        if all_causes == set(): return BottleneckCause.UNKNOWN

        if all(cause in [SwitchCause.FUTEX_WAKE, SwitchCause.FUTEX_WAIT] for cause in all_causes):
            return BottleneckCause.SYNCHRONISATION

        if all(cause in [SwitchCause.IO] for cause in all_causes):
            return BottleneckCause.IO

        return BottleneckCause.UNKNOWN

    def synchronisation_keys(self):
        return set([entry.assoc_futex_key for entry in self.entries if entry.assoc_futex_key != ""])

    def file_keys(self):
        return set([entry.assoc_file_key for entry in self.entries if entry.assoc_file_key != ""])


def postprocess(cm_critical_entries, args):
    """
    :type cm_critical_entries: dict[string, CMetricEntryCollection]
    """
    for _, entry in cm_critical_entries.items():
        entry.combine_samples(args)


def merge_cmetric_entries(cmetric_reports, crit_stack_trace_cm_sums):
    for entry in cmetric_reports:
        # Combine all call paths irrespective of CMetric value and then sort as per CMetric value
        if entry.stack_trace not in crit_stack_trace_cm_sums:
            crit_stack_trace_cm_sums[entry.stack_trace] = CMetricEntryCollection()

        crit_stack_trace_cm_sums[entry.stack_trace].add(entry)