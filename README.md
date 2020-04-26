# MGAPP

>GAPP is a profiler to detect serialization bottlenecks in parallel Linux applications. It works by tracing kernel context switch events by kernel probes managed using the extended Berkeley Packet Filter (eBPF) framework. It has been tested on multi-threaded and MPI C/C++ applications.
> &mdash; The [GAPP README](https://github.com/RN-dev-repo/GAPP).

This repository was is an imaginatively named modified version of [GAPP](https://github.com/RN-dev-repo/GAPP) (Generic Automatic Parallel Profiler -
[corresponding publication](https://arxiv.org/abs/2004.05628)),
and was developed as part of my master's project in 2018-2019.
GAPP was developed by Reena Nair at Imperial College alongside Tony Field, both of whom helped greatly with this.

The same prerequisites as [GAPP](https://github.com/RN-dev-repo/GAPP) are required.

Some of the main things that were added are:

1. Classificiation of critical stack traces (I/O, synchronisation)
1. Metadata about events
   * I/O file name
   * Socket address
1. Waker / woken traces for synchronisation events where possible
1. Analysis for individual locks that were detected
1. A terminal-based GUI
1. Some general QoL improvements:
   * Simplifying some common C++ stack trace patterns
   * Ability to spawn processes rather than tracking existing ones (and also to attach to a specific PID)

Some explanation is available in the [associated report](./Report.pdf), although it was intended
as my dissertation, and as such is *not* a condensed form of documentation.

## Usage

A common usage example:

```shell
sudo ./mgapp.py -e path -s bin/mutex
```

The `-e` flag enables enhanced stack trace reporting, `path` indicates that you will be providing a path to the application
to be traced, and `-s` indicates you would like `mgapp.py` to spawn the process for you (rather than attaching to one you will
spawn yourself).

Thus, this is in some level equivalent to:

```shell
sudo ./mgapp.py -e path bin/mutex
```

And then running `bin/mutex` separately in another tab, leaving a sufficient delay (a few seconds) for `mgapp.py` to set up the appropriate kernel
probes (which do not need the program to be running to set up).

Most of the flags from the original version of GAPP are still in place and functional. I would suggest reading the
[primary repository's documentation](https://github.com/RN-dev-repo/GAPP) for more advanced usage instructions.

## Disclaimer

The software in this repository has not been extensively tested and is likely to have a number of bugs and issues.

Please feel free to get in touch via email or a Github issue about anything you think might be broken, or if you have any questions
related to usage, and I will be more than happy to help where possible.

Finally, to reiterate what was stated at the top, much of this repository is based on the fantastic work by Reena Nair and Tony Field.
I highly recommend reading the [publication for GAPP](https://arxiv.org/abs/2004.05628).

