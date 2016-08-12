BCC Documentation
================================================================================

Purpose
--------------------------------------------------------------------------------

This document is intended to contain knowledge pertaining to the BCC tool suite
used to compile C functions into BPF and attach them to probes in the kernel and
in userspace. For more information on BPF, see the [BCC docs]
(https://github.com/iovisor/bcc/tree/master/docs) and [the BPF MemSQL docs]
(02_bpf.md). 

Introduction
--------------------------------------------------------------------------------

BCC ("the BPF Compiler Collection") is a tool suite used to write BPF
instrumentation for linux probes, including kernel tracepoints, kprobes,
uprobes, and userspace static (USDT) probes. It is open source and maintained by
a company called Plumgrid, but it seems Facebook is gaining interest in the
technology. 

At it's core, BCC is an LLVM backend for BPF assembly, a library which
encapsulates this backend and a C frontend, Python and Lua bindings for this
library, and many scripts and examples that use BPF. 

As of 8/5/16, BCC was only at 0.1.8. Its API is not stable, and expect that your
scripts will break, even if the version number does not get bumped. The
distribution packages are tied to git. If you need a somewhat stable interface,
build it yourself (it's not too difficult). But if you do, just remember to set
`LD_PPRELOAD` and `PYTHONPATH` appropriately (to point to the correct places in
the build directory). Or maybe you have a better way.

There is also a good mailing list for the project (iovisor-dev) [1]. It's not too
busy, but they are quite receptive to questions and feature requests.

There is some overlap between this document and the [MemSQL BPF documentation]
(02_bpf.md). 

There were some issues I had with the BCC. I had to make a few modifications to
get some things to work; they are included in the `patches/` directory. 

Writing Scripts
--------------------------------------------------------------------------------

*Firstly, see the BCC docs and tutorials [3]*

The programming style for these scripts is really "C-in-Python" sort of thing.
You will have a Python multi-line string that contains the C instrumentation
code, the Python will perform substitutions in the C code based on arguments to
the Python script, set up the probes, etc. The C code may, for instance, filter
on a plan id that is passed to the Python script as an argument. The Python 
script will then just replace some known identifier in the C code with the
passed-in value. 

As described in the MemSQL BPF docs, all memory accesses off the BPF stack are
forbidden by the BPF verifier; the only way to access memory off the stack is
through the BPF helper function `bpf_probe_read`. However, BCC in some cases
will allow you to dereference a pointer to off-stack memory and its Clang
rewriter will automatically rewrite your code to have a call to `bpf_probe_read`
(though this is not perfect; see the Debugging section below).

The primary data structure in BCC is the Python class `BPF`. It takes a string
containing the C program and some debugging flags. It also has methods for
attaching functions in the C program to kprobes or tracepoints. The `BPF` object
is used as an argument when attaching to a USDT probe.

USDT probes have a separate data structure, called a `USDT`. In earlier versions
of BCC, there were several objects, like `USDTReader`, `USDTArgument`,
`USDTProbe`, etc. The place to look is [`bcc/src/python/bcc/usdt.py`]
(https://github.com/iovisor/bcc/blob/master/src/python/bcc/usdt.py).

### Filtering by Plan ID

When I (Kyle) was writing my scripts, I chose to use the Plan ID as the means by
which to filter on particular queries. This requires the user to have executed
their query at least once, and look up the plan ID in the plancache. Ideally the
user would just be able to pass in a string that matched the query they wanted
to filter on, like the parameterized query string, but you cannot do `strcmp` in
BPF because that requires loops. There is some talk of a solution to this
though; see this thread: [6]. The nice thing about plan id is that it is
available easily to the `querystart` and `queryend` probes; those probes can
just set and unset a field in a map from thread id to bool or whatever
(effectively a thread-local flag variable), and all other threads can just check
that variable.

### PLY and Pure Lua

Small side note. PLY [4] appears to be a dtrace-like syntax or frontend for the
BCC tooling, which would be awesome. As of 8/8/16, though, development seems to
have stopped five months ago (last commit 3/8/16). 

As of 8/8/16, there also appears to be a pull request which adds the ability to
write pure-lua scripts. That is, currently you can write C-in-Python or C-in-Lua
scripts, as described above and in the MemSQL BPF documentation, but this pull
request adds the ability to write the instrumentation in Lua as well -- I think
it's just an LLVM frontend for the BPF backend. See BCC issue 626 [5].

Debugging 
--------------------------------------------------------------------------------

First, make sure you are passing `debug=bcc.DEBUG_BPF|bcc.DEBUG_PREPROCESSOR` to
the `BPF` constructor in your script so you can see your preprocessed C script
and the BPF assembly.

### Common Issues

Everything has to be run with root privileges.

If you see an error like

    LLVM ERROR: Program used external function '_bpf_readarg_querystart_2' which
    could not be resolved!

It probably means you are not passing in the `bcc.USDT` python object you
created to the `bcc.BPF` constructor. The error is referring to a function
generated to support a call to `bpf_usdt_readarg`. 

### Clang Rewriter Bug

If you see something like 

    /virtual/main.c:373:54: error: cannot take the address of an rvalue of type 'typeof(struct rq *)' (aka 'struct rq *')
      ...&({ typeof(struct rq *) _val; memset(&_val, 0, sizeof(_val)); bpf_probe_read(&_val, sizeof(_val), (u64)cfs_rq + offsetof(struct cfs_rq, rq)); _val; })...
         ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It may be related to a bug in the clang rewriter, see BCC issue 622 [2]. What
appears to be happening is a redundant insertion of a `bpf_probe_read` when
reading in `struct rq *rqp`, and the inserted code attempts to take the address
of a GCC statement expression (a code block), which is an rvalue.

To get rid of this, you can modify the BCC library by just gutting the rewriter
capability related to this and building the binary from source. Specifically, it
is in `ProbeVisitor::VisitMemberExpr` in
[`bcc/src/cc/frontends/clang/b_frontend_action.cc`]
(https://github.com/iovisor/bcc/blob/master/src/cc/frontends/clang/b_frontend_action.cc). 
Or you can just apply
[`patches/bcc/0002-remove-clang-rewriter-for-pointers.patch`]
(/patches/bcc/0002-remove-clang-rewriter-for-pointers.patch).

### write(...) failed: Device or resource busy

If you get an error like

    write(/sys/kernel/debug/tracing/uprobe_events, "p:uprobes/p__var_lib_memsql_memsqld_0xffffffffffc0000c /var/lib/memsql/memsqld:0xffffffffffc0000c") failed: Device or resource busy
    Traceback (most recent call last):
      File "./query_memory.py", line 138, in <module>
        b = BPF(text=text, debug=debug, usdt=u)
      File "/Volumes/developer/bcc/src/python/bcc/__init__.py", line 199, in __init__
        if usdt: usdt.attach_uprobes(self)
      File "/Volumes/developer/bcc/src/python/bcc/usdt.py", line 48, in attach_uprobes
        bpf.attach_uprobe(name=binpath, fn_name=fn_name, addr=addr, pid=pid)
      File "/Volumes/developer/bcc/src/python/bcc/__init__.py", line 607, in attach_uprobe
        raise Exception("Failed to attach BPF to uprobe")
    Exception: Failed to attach BPF to uprobe

this may be because the probe shows up multiple times in the ELF notes section 
with the same address. E.g., you look in the notes section and find something 
like:

    /var/lib/memsql/memsqld memsqld:execstats_addmemoryuse [sema 0x0]
      location 0x14fae90 raw args: 8@-16(%rbp)
        8 unsigned bytes @ -16(%rbp)
      location 0xc raw args: 8@-16(%rbp)
        8 unsigned bytes @ -16(%rbp)
      location 0xc raw args: 8@-16(%rbp)
        8 unsigned bytes @ -16(%rbp)
      location 0xc raw args: 8@-16(%rbp)
        8 unsigned bytes @ -16(%rbp)
      location 0xc raw args: 8@-16(%rbp)
        8 unsigned bytes @ -16(%rbp)

Clearly something has gone wrong with the USDT macro: `0xc` does not make sense
as a valid offset. This, actually, is not the cause of the error above; it turns 
out you can attach a uprobe here without a problem. The issue is actually just
attaching to the same probe at the same location multiple times. Apply 
[`patches/bcc/0001-duplicate-low-probe-address-handling.patch`]
(/patches/bcc/0001-duplicate-low-probe-address-handling.patch) to resolve this 
issue.

Interesting BCC Scripts
--------------------------------------------------------------------------------

[`argdist`]
(https://github.com/iovisor/bcc/blob/master/tools/argdist_example.txt) is an 
interesting tracing tool. One-liners that seem to work:

    # to print out each query as it is executed
    sudo PATH=$PATH:/var/lib/memsql/ argdist -v -C "u:memsqld:querystart(char* arg1):char*:arg1"

    # to print out a histogram of the cumulative query latencies:
    sudo PATH=$PATH:/var/lib/memsql/ argdist -v -H "u:memsqld:queryend(u64 arg1):u64:arg1"

Adding a simple probe to the background flusher's loop, I get the thread IDs of
the background flusher threads every time they run:

    sudo PATH=$PATH:/var/lib/memsql/ argdist -v -C 'u:memsqld:backgroundflusher():u32:$PID'

This showed me that the background flusher thread runs every 5 seconds. Funny
that dynamic tracing can be used as sort of a learning tool.

Added a probe to `SnapshotAndLogManager::BeginSnapshot`, and you can trace with

    sudo PATH=$PATH:/var/lib/memsql/ argdist -v -C 'u:memsqld:beginsnapshot(char*, char*):u32:$PID'

or replace the tail with

    :char*:arg1
    # or
    :char*:arg2

to get the snapshot file name and the database name, respectively. You can do
similar things for the error probe.


[`trace`](https://github.com/iovisor/bcc/blob/master/tools/trace_example.txt) 
is another BCC tracer tool.  

    # tracing with bcc/trace:
    sudo PATH=$PATH:/var/lib/memsql/ trace 'u:memsqld:querystart "%s", arg1'


Bibliography
--------------------------------------------------------------------------------

* [1] [IOVisor-dev Mailing List](http://lists.iovisor.org/mailman/listinfo/iovisor-dev)
* [2] [BCC Issue #622](https://github.com/iovisor/bcc/issues/622)
* [3] [BCC Docs](https://github.com/iovisor/bcc/tree/master/docs)
* [4] [IOVisor's PLY Project](https://github.com/iovisor/ply)
* [5] [BCC Issue #626](https://github.com/iovisor/bcc/issues/626)
* [6] [String Comparison Question on the IOVisor Mailing List](http://lists.iovisor.org/pipermail/iovisor-dev/2016-July/000319.html)
