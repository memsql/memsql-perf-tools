BPF Scripts
================================================================================

This repository contains the dynamic tracing scripts and documentation about BPF and BCC.
It is mainly geared towards MemSQL performance engineers who may want to write BPF scripts, 
but it may be useful to the general public as some basic examples of BPF and BCC.

`docs/` contains various text files including notes and presentations.

`tools/` contains the BPF/BCC programs

`patches/` includes some patches for BCC to get some of my tools working

Documentation
--------------------------------------------------------------------------------

Before reading anything but the Introduction, I would recommend reading the [BCC
project's README](https://github.com/iovisor/bcc) and [their documentation]
(https://github.com/iovisor/bcc/tree/master/docs). 

[Introduction](docs/01_intro.md) - An introduction to (mostly Linux) tracing
technologies. 

[BPF](docs/02_bpf.md) - what is BPF and how to write it

[Kernel](docs/03_kernel.md) - information about kernel internals sometimes 
useful for writing certain kinds of scripts

[BCC](docs/04_bcc.md) - tips and tricks regarding the BPF Compiler Collection
(BPF)

Tools
--------------------------------------------------------------------------------

These scripts vary in their level of completion. Note also that these tools are
meant primarily as a resource for people looking to use BCC / BPF. Support for 
USDT probes in MemSQL is experimental and versions of MemSQL earlier than 5.1.3
do not support any USDT probes.   

Scripts that work:

* `query_latency.py` - simple script that traces queries' latencies. Can filter
  on plan ID. 
* `query_memory.py` - traces queries' memory usage. Can filter on plan ID.
* `futexes.py` - traces futex syscalls' latencies. Can filter on process and
  query plan ID. Note that when filtering it tends to hang after a few seconds.
  Not sure why.  
* `partition.py` - Traces the probes for all the low-level commands in the 
  clustering / partition sharding code. Make sure you point it at the exact
  binary from which the node you want to trace was launched. See the help for
  this tool, or [the MemSQL BPF doc's debugging section]
  (docs/02_bpf.md#your-probe-which-counts-something-like-probe-hits-attaches-without-errors-but-it-is-reporting-a-count-of-0)
  for more info.

Scripts that don't work: 

* `query_bio.py` - Derived from the bcc `biosnoop` utility, but
  augmented to support filtering based on query.  
* `query_tsa.py` - A script for thread-state analysis. For some
  reason, some of the important probe instrumentation appears not to be firing.
  Uses kernel tracepoints, and thus requires Linux version >= 4.7
* `query_tsa_old.py` - Like `query_tsa.py`, but does not use tracepoints, and is
  in less of a working state. 

To those not using MemSQL, `query_tsa.py` and `futexes.py` probably will be most
interesting.
