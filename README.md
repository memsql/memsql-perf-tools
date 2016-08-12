BPF Scripts
================================================================================

This repository contains the dynamic tracing scripts and documentation developed
over the past few months at MemSQL. It is mainly geared towards MemSQL
performance engineers who may want to write BPF scripts, but it may be useful to
the general public as some basic examples of BPF and BCC.

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
meant primarily as a resource for people looking to use BCC / BPF. Current 
versions of MemSQL do not ship with USDT probes and do not work with these
scripts, only an internal development version.

Scripts that work:

* `query_latency.py` - simple script that traces queries' latencies. Can filter
  on plan ID. 
* `query_memory.py` - traces queries' memory usage. Can filter on plan ID.
* `futexes.py` - traces futex syscalls' latencies. Can filter on process and
  query plan ID. Note that when filtering it tends to hang after a few seconds.
  Not sure why.  

Scripts that don't work: 

* `partition.py` - Does not work, not sure why. Traces the probes for all the
  low-level commands in the clustering / partition sharding code.
* `query_bio.py` - Derived from the bcc `biosnoop` utility, but
  augmented to support filtering based on query.  
* `query_tsa.py` - A script for thread-state analysis. For some
  reason, some of the important probe instrumentation appears not to be firing.
  Uses kernel tracepoints, and thus requires version >= 4.7
* `query_tsa_old.py` - Like `query_tsa.py`, but does not use tracepoints, and is
  in less of a working state. 

To those not using MemSQL, `query_tsa.py` and `futexes.py` probably will be most
interesting.
