BPF Documentation
================================================================================

History
--------------------------------------------------------------------------------

BPF stands for 'Berkeley Packet Filter'. It was originally developed as a means
of writing just that (packet filters) without modifying the kernel or building a
kernel module. Cloudflare uses it for their product [1]. In the past few years,
there was a movement to augment BPF, and the result was eBPF (extended BPF). BPF
instrumentation code can now be attached to kprobes, kernel tracepoints, and uprobes.

Kernel Requirements
--------------------------------------------------------------------------------

Support for this stuff really only came out in the late 3.x kernels, but you
really need 4.1 or 4.4 to do anything. See the BCC docs for more details on
kernel support [3]. 

Execution Environment
--------------------------------------------------------------------------------

BPF programs execute in a restricted environment to ensure they don't crash or
hang the kernel. The BPF verifier in the kernel ensures these restrictions hold.
There is an instruction limit and nesting limit to guarantee this. For the type
of code needed for instrumentation, you will not frequently be impeded by the
instruction count. However, the fact that there are no loops or backwards jumps
allowed, and there is a maximum nesting level, is pertinent.  Remeber that basic
things like string comparisons require loops. For such things, you must hope
that there is a BPF helper function you can call out to (see below). 

Programming Style + API
--------------------------------------------------------------------------------

*See Also: the BCC docs and tutorials written [4]*

The programming style for these scripts is really a "C-in-Python" sort of thing.
You will have a Python multi-line string that contains the C instrumentation
code, the Python will perform substitutions in the C code based on arguments to
the Python script, set up the probes, etc. See the documentation regarding BCC
for more details on this. 

When writing the C scripts, there are a few things to keep in mind. First, you
are programming in the kernel. You do not have to worry about crashing or
hanging the kernel; the verifier will take care of this for you.  As described 
above, there are no loops, backwards jumps, and limited nesting. I believe all
functions you define that are to be called by functions attached to probes must
be `static inline`. You also cannot access any memory off your stack without a
call to `bpf_probe_read` (sort of like `copy_to_user` and `copy_from_user`, if
you are familiar with those) (note that some calls to `bpf_probe_read` can be
elided; see the [MemSQL page on BCC](04_bcc.md)).

### Kernel Headers
You have access to the exported kernel headers, e.g. things in the `include/`
directory at the top level of the Linux source tree. BCC will take care of
locating these headers that you include. Other internal headers for subsystems
may be more difficult.  A workaround is to copy them into your script, but note
this is error-prone. BCC will also take care of defining the proper `CONFIG_`
macros, but it is still easy to mess up when copy-pasting. According to BCC
issue 622 [6], there is a way to get the internal headers like `sched.h`:

> Include of sched.h is possible if 'build' and 'source' dirs are known. Most
> likely something like include "../../kernel/sched/sched.h" should have
> worked.

but it sounds like you will need to have the sources for the kernel you are
running (with all distribution patches applied, etc.).

### BPF Helper Functions

There are a few functions defined in the kernel that can be called from BPF
code. They act as helper functions written in C in the regular kernel, and are
used by BPF scripts to offload unsafe work to them. I believe these are defined
in the `enum bpf_func_id` in [`include/uapi/linux/bpf.h`]
(http://lxr.free-electrons.com/source/include/uapi/linux/bpf.h?v=4.7). Some 
relate to packet filtering, and which are mostly uninteresting for tracing. 

There are also a couple BCC files
([`bcc/src/cc/compat/linux/bpf.h`](https://github.com/iovisor/bcc/blob/master/src/cc/compat/linux/bpf.h) and
[`bcc/src/cc/compat/linux/virtual_bpf.h`](https://github.com/iovisor/bcc/blob/master/src/cc/compat/linux/virtual_bpf.h))
that have references to the helper functions. They should be the same as the
ones defined in the kernel. 

Functions are called via the `BPF_CALL` opcode. Taken from
`include/uapi/linux/bpf.h` [8]:

> integer value in 'imm' field of BPF_CALL instruction selects which helper 
> function eBPF program intends to call

`bpf_probe_read` is an important helper function; as mentioned above, it is
required to read from memory off your stack. `bpf_trace_printk` is like a
`printk`, but can be read using BCC's `trace_fields()` method. There are also
the functions that operate on maps like `increment`, `lookup`, and `update`.
These are frequently used in BPF scripts. 

### LLVM Builtins

In an attempt to allow filtering based on query strings, I investigated LLVM
string builtins like `__builtin_memcmp` and `__builtin_strstr`. They did not
work -- they failed in the verification stage.

Debugging
--------------------------------------------------------------------------------

To figure out what kprobe points are available to you (i.e., which functions are
not inlined) you can `grep` `/proc/kallsyms`, which contains all the symbols of
the running kernel. Note that this is true event though kernels are stripped of
symbols by default. 

### Common Issues

#### Your probe which counts something (like probe hits) attaches without errors, but it is reporting a count of 0
If you are attaching to a tracepoint, it may not be there. This happened with
some of the scheduler tracepoints: for those, you need to have
`CONFIG_SCHEDSTATS`. Make sure you have the proper configs for the tracepoints
you are using. Note that tracepoints may show up in `perf list` even if you do
not have the proper configs for them. 

You can rule this out by using ftrace to trace the same tracepoint or kprobe you
are working with. This will let you see if the probe is actually getting hit or
not, as the default for ftrace is to just print out the number of hits. See the
[kernel documentation for ftrace]
(https://www.kernel.org/doc/Documentation/trace/ftrace.txt) for how to do this 
[5].

You can also just change the aggregation code in your script to be a
`bpf_trace_printk()` call to see if the thing is actually firing. 

Make sure that the arguments to your instrumentation functions are correct; I
found that two of my (USDT) snapshot probes were not firing because I had
declared as arguments to the instrumentation function the parameters to the
probe, whereas I should have just had one parameter (`pt_regs *ctx`) and
accessed the parameters with `bpf_usdt_readarg`.

It may be that ftrace as well (via `/sys/kernel/debug/tracing/uprobe_profile`)
is reporting that you have USDT (uprobes) attached, but they are not being hit.
You are also not seeing anything from your BPF script, which is why you looked
to ftrace in the first place. It may be that you are tracing the wrong binary. I
discovered this when running `partition.py`. Make sure that if you are running a
cluster, you know which node will exercise the logic you want to trace. You must
pass a path to the real path from which that binary was launched, not an
identical binary elsewhere. Or, use the pid. I do not know why an identical
binary elsewere does not work; but I guess you cannot trace all USDT probes
across a system with multiple binaries having the same USDT probes without one
tracing script attached to each of the binaries. The way I debugged this was
by attaching to a leaf with GDB and breaking right near one of my tracepoints
that wasn't getting hit; the breakpoint didn't get hit either, which meant
what I wanted to trace was not being exercised on the leaf. So I attached to
the master, the breakpoint hit, and then I pointed my `partition.py` at the
master's real binary path. 

There was one bug I (Kyle) had where I had `CONFIG_SCHEDSTATS`, and ftrace
reported the probes were being hit, but my instrumentation was not being run (at
least it appeared that so; they were simple counters). Also, the `futexes.py`
script I wrote has an issue (8/5/16) where after a few seconds the counters stop
incrementing; i.e., it appears the instrumentation code stops running. YMMV.

#### BPF stack errors (i.e. "invalid indrect read from stack off...")

If you get an error like 

    invalid indirect read from stack off -150+0 size 5

or 

    !read_ok

(when you are attaching with `bcc.DEBUG_BPF` enabled (I think you need that to
see the verifier error messages and BPF assembly)), then it means you are doing
an invalid read *from your own stack*, not from the outside world. I.e., there
is something on your stack that might not be initialized. The typical solution
involves initializing your struct or array on the stack like:

    char query_str[6] = {0};
    //or
    struct val_t = {0};

Or it may be that you are not initializing an argument correctly, e.g.

    u64 arg1; // change to u64 arg1 = 0;
    bpf_usdt_readarg(1, ctx, &arg1);

Whereas if you get something like `invalid ... mem access instruction 'inv'` or
something you are accessing something from the arguments or off your stack or
above your stack frame and should probably try wrangling with `bpf_probe_read`.

If you get an error message like:

    LLVM ERROR: Cannot select: 0x29e97a0: ch,glue = BPFISD::CALL 0x1e16d00,
    0x29c4f50, 0x29b9240, 0x2ac89b8, 0x29e9550, 0x1e16d00:1 [ORD=4] [ID=40]
      0x29c4f50: i64 = TargetExternalSymbol'memset' [ID=9]
      0x29b9240: i64 = Register %R1 [ID=6]
      0x2ac89b8: i64 = Register %R2 [ID=7]
      0x29e9550: i64 = Register %R3 [ID=8]

It probably means you are trying to load something too large onto the stack see
BCC issue 212 [6].

#### Other verifier messages

To understand messages the verifier gives you, see the kernel documentation
`Documentation/networking/filter.txt` under the section 'Understanding eBPF
verifier messages' [2]. Also see the [BCC Docs]
(https://github.com/iovisor/bcc/tree/master/docs) [4].


See Also
--------------------------------------------------------------------------------

* [`bpf(2)` `man` pages](http://man7.org/linux/man-pages/man2/bpf.2.html).
* The kernel Documentation 'networking/filter.txt' [2]
* The BCC docs and tutorials [4]

Bibliography
--------------------------------------------------------------------------------

* [1] [Cloudflare Blog, "BPF: The Forgotten Bytecode"](https://blog.cloudflare.com/bpf-the-forgotten-bytecode/)
* [2] [Networking Filter Kernel Documentation](https://www.kernel.org/doc/Documentation/networking/filter.txt)
* [3] [BCC Kernel Versions documentation](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)
* [4] [BCC Docs](https://github.com/iovisor/bcc/tree/master/docs)
* [5] [Ftrace Kernel Documentation](https://www.kernel.org/doc/Documentation/trace/ftrace.txt)
* [6] [BCC Issue 212](https://github.com/iovisor/bcc/issues/212)
* [7] [BCC Issue 622](https://github.com/iovisor/bcc/issues/622)
* [8] [Linux `include/uapi/linux/bpf.h:143`](http://lxr.free-electrons.com/source/include/uapi/linux/bpf.h#L143)
