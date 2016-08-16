Introduction to Linux Tracing
================================================================================

Contents
--------------------------------------------------------------------------------

* History of tracing
* Ftrace
    * Kprobes/uprobes
    * Static tracepoints
* USDT
* Gdb support
* System tap
* LTTng
* Bibliography + see also (dtrace guide)

History of Tracing
--------------------------------------------------------------------------------

Read about DTrace if you don't know what it is. [1] 

Ftrace
--------------------------------------------------------------------------------

Ftrace is the linux "Function Tracer", originally used to provide insight into 
what the kernel is doing, but has since evolved from that to be an interface to
krobes, uprobes, and static tracepoints. See [3] for more information. Ftrace is
pretty neat, and may be useful for performance investigations in its own right.

Its interface is through the `/sys/kernel/debug/tracing` filesystem. It is
useful if you need to debug your BPF script -- e.g., maybe it seems like your
probe isn't firing. You can set a kprobe manually through the ftrace filesystem
interface to see if it fires there, and isolate whether it is just your BPF
script (or the BPF subsystem and tooling) *or* the system itself (e.g. maybe the
function you are probing on got inlined). 

It looks like ftrace might support userland stacktraces with the
`userstacktrace` option [3]:

    This option changes the trace. It records a stacktrace of the current
    userspace thread. 

Sounds like ftrace supports tracing on a single thread. The documentation 
describes how to enable events on a per-thread basis using set_ftrace_pid [3].

### Kprobes

Kprobes are probes in the Linux kernel which can be placed on almost any
function (and also function return, called "kretprobes"). BPF scripts can be
attached to krobes and kretprobes. 

If you are going to use kprobes on their own (without BPF and BCC), do not use 
the C interface defined in the kernel documentation for kprobes [4]. Instead,
just use the ftrace interface defined in the aforementioned kernel documentation
for ftrace [3]. It's `/sys/kernel/debug/kprobes` and
`/sys/kernel/debug/tracing/kprobe_{events,profile}`.

Note that there is a blacklist for kprobes, that is, functions which are not
allowed to be probed. Important things like pagefaults cannot be traced with
kprobes (because kprobes are implemented using the pagefault handler, I
believe). You can find the blacklist in `/sys/kernel/debug/kprobes/blacklist`.

### Uprobes

Uprobes are the userspace analogy of kprobes. For an introduction to uprobes,
see Brendan Gregg's article [5] and the uprobe tracer kernel documentation [6]. 
Uprobes have a similar interface to kprobes regarding the filesystem, but have a
more complicated signature syntax. This syntax is exposed in different ways
(e.g. compare Brendan Gregg's tool in the aforementioned article [5] to BCC's
`argdist` [7] and to the syntax in the uprobe documentation [6]).

### Static Tracepoints

Kernel static tracepoints are a workaround for the few functions that are on the
kprobes blacklist, and actually make tracing a lot easier. They are placed at strategic
locations throughout the kernel and, unlike the kernel structure of function
names and function calls, are stable. They look kind of like USDT probes, in
that they have a sort of 'group' (AKA 'provider' or subsystem), a 'name', and parameters you can access. Very
useful. As of 4.7 you can attach BPF programs to them. See [8], [9] and [10].

USDT
--------------------------------------------------------------------------------

"Userland Dynamic Tracing." A technique pioneered by DTrace to bring dynamic
tracing to userland whereby a small macro is added to the source code at the
probe point. On the surface, it looks similar to kernel static tracepoint
macros. Unlike kernel static tracepoints, USDT macros include a directive to the
linker to include information in the ELF `.notes` section (which can be read
with `readelf -n` or BCC's `tplist`) which contains information like the offset
of each location of probe in the binary, where its parameters are, etc. 

There is SystemTap support for these as well (see below).

Examples:

  * MySQL: https://dev.mysql.com/tech-resources/articles/getting_started_dtrace_saha.htm
    and (most useful): http://dev.mysql.com/doc/refman/5.7/en/dba-dtrace-server.html
  * Postgres: https://www.postgresql.org/docs/current/static/dynamic-trace.html 
  * Java: http://docs.oracle.com/javase/6/docs/technotes/guides/vm/dtrace.html 

The macro is something like 

    DTRACE_MACRO2(memsqld, querystart, query, planid);

This macro resolves to a few `mov` instructions to setup the arguments for the
macro, and then a `nop` instruction.  When a dynamic tracer (such as a BPF,
SystemTap, or Dtrace script) is attached to the process, this nop instruction is
replaced by a trap into the kernel to trigger the instrumentation code. The
instrumentation code can access the probe's parameters.

To add a probe, you must `#include <sys/sdt.h>`. This header requires the
Systemtap development package. Note that
there is no dependency whatsoever on Systemtap itself other than this simple
header file which defines a few standard macros used by many tools.

Tracing USDT "probes" is accomplished through uprobes. Really, USDT "probes" are
just macros (`DTRACE_PROBE2`) that add some assembly for the probe's `nop`
instruction, and a directive to the linker to add some information about the
"probe" location and its arguments to the ELF notes section. Tracers consume
this information and use it to set a uprobe. 

To list the probes in a binary nicely, you can use the BCC tool [`tplist`]
(https://github.com/iovisor/bcc/blob/master/tools/tplist_example.txt),  e.g.

    tplist -l [-v] -p $(pidof memsqld)

Here is the disassembly of the area around a probe. One of this probe's
arguments requires a method call. Probe's arguments are passed in registers.

Without probe enabled:

    MemsqlAutoParamExecute
    0x188a45c           lea    -0x500(%rbp),%eax
    0x188a462           mov    %rax,%rdi
    0x188a465           callq  0x14f48fe 
    0x188a46a           mov    -0x2a3b0(%rbp),%rax
    0x188a471           nop                             # DTRACE_PROBE1(...)
    0x188a472           lea    -0x292c0(%rbp),%rax
    0x188a479           mov    %rax,%rdi

With probe enabled:

    0x188a45b <+5599>:  lea    -0x500(%rbp),%rax
    0x188a462 <+5606>:  mov    %rax,%rdi
    0x188a465 <+5609>:  callq  0x14f48fe 
    0x188a46a <+5614>:  mov    -0x2a3b0(%rbp),%rax
    0x188a471 <+5621>:  int3                            # DTRACE_PROBE1(...)
    0x188a472 <+5622>:  lea    -0x292c0(%rbp),%rax
    0x188a479 <+5629>:  mov    %rax,%rdi

Sometimes, a USDT probe may require some relatively heavy computation to
generate a probe parameter; e.g., make a function call, or what have you. It is
possible to disable this computation unless a dynamic tracing tool is actually
attached to the probe. There is a small flag in the binary, referred to as the
probe's "semaphore" which can be set to enable or disable this computation at
runtime. (__Note that in the dynamic tracing community, or maybe specifically
the System Tap and BPF communities, "enabling" a probe means setting its
semaphore, not just normally using a regular probe.__) Not sure what the status
of semaphores is in BPF. 

But I think we can probably avoid semaphore-guarded static-tracepoints, at least
initially. Such probes are supposed to be used when the arguments to the probe
are expensive and dynamically constructed, but, taking the query start and stop
probes as an example, the query string is already there, we just need the probe
to take one `char*` argument which points to that query string.

For reference, here is a portion of the ELF notes section:

    $ tplist -vl /var/lib/memsql/memsqld
    /Volumes/developer/memsql/debug/memsqld memsqld:queryend [sema 0x0]
      location 0x188cba2 raw args: 8@%rbx -8@%rax
        8 unsigned bytes @ register %rbx
        8   signed bytes @ register %rax
    
    /Volumes/developer/memsql/debug/memsqld memsqld:backgroundflusher [sema 0x0]
      location 0x18b4936 raw args:
    
    /Volumes/developer/memsql/debug/memsqld memsqld:beginsnapshot [sema 0x0]
      location 0x3114992 raw args: 8@%rax 8@-1400(%rbp)
        8 unsigned bytes @ register %rax
        8 unsigned bytes @ -1400(%rbp)

Note that there is an issue with USDT where sometimes a probe has multiple
locations with the same address, typically a unreasonably low address. For more
info and a fix, see the [MemSQL BCC page](04_bcc.md).

### See Also
* SystemTap Wiki page on the implementation of user-space probes [13]. 
* SystemTap Wiki page on adding user-space probes to programs [12].
* the SystemTap section below
* [Sasha Goldshtein's blog post] 
  (http://blogs.microsoft.co.il/sasha/2016/03/30/usdt-probe-support-in-bpfbcc/)
  from when he originally added USDT support to BCC. [15]

GDB
--------------------------------------------------------------------------------

GDB continues to have features added to it.

`info probes` will show the names of all STPs (statically-defined probes) in
the attached binary. You can `enable` and `disable` probes, presumably to break
on. [14]

E.g.:

    $ sudo gdb -batch -pid 26601 -ex "info probe"
    Type Provider   Name        Where               Semaphore Object
    [snip]
    stap memsqld    queryend    0x000000000188cb24  /Volumes/developer/memsql/debug/memsqld
    stap memsqld    querystart  0x000000000188a471  /Volumes/developer/memsql/debug/memsqld
    [snip]

I had a little difficulty with GDB detaching from `mysqld` if you run `info
probes` from the interactive prompt, so I recommend doing  `sudo gdb -batch 
-pid $(pidof mysqld) -ex "info probe"`.

Breaking on the probe in gdb seems to cause a segfault, as in:

    $ break -probe-stap memsqld:querystart
    Breakpoint 1 at 0x188a471   # address matches the 'Where' column above

Brief investigation revealed nothing obvious.

System Tap
--------------------------------------------------------------------------------

Brendan Gregg seemed to think System Tap wasn't quite stable though he still
recommends it [2]. It is basically dtrace for linux. Note that for 16.04, the
package for system tap had userspace tracing disabled from some braindead reason
(it believes Ubuntu compiles the kernel without support for uprobes, which is
not true anymore). I had to compile from source (I used git tag release-3.0) and
had to fix the install script, which was a little concerning (I was installing
to a nonstandard prefix for non-root build; nonetheless, concerning).

To use System Tap, you can create a tapset, let's say called `probes.stp`, that
looks like

    probe querystart = process("memsqld").provider("memsqld").mark("querystart")
    {
            query = $arg1;
            planid = $arg2;
            probestr = sprintf("%s(query=%s, queryid=%lu)", $$name, user_string(query), planid);
    }

[12] and then with the following incantation, you can trace your probe:

    sudo PATH=$PATH:/Volumes/developer/memsql/debug/ \
        stap -I. -v -e 'probe querystart { println(probestr) }'

(you need the binary in your path for the `process("memsqld")` part to work)
(note that if you run this and get a horrifying compiler error, you may be on
the wrong kernel version; e.g. I think I compiled my SystemTap on a 4.4 machine,
tried running it 4.7, got a scary error, then rebooted into 4.4, and all was
well).

There also appears to be a new runtime for system tap that uses BPF [11].

By creating a `.d` file with probe definitions in the System Tap language, and
then passing this file through System Tap's `dtrace` tool with the proper
incantations, it will give you a `.h` file you can include (rather than
`sys/sdt.h` which will give you  macros with names that match the probe name.
E.g., rather than the `DTRACE_PROBE2(provider, name, arg1, arg2)` as above, you
have `MEMSQL_QUERY_START(arg1, arg2)`. The only difference in the ELF notes
section is it appears there is a probe semaphore created, i.e., it has a
non-null "Semaphore" entry. In order to get the names of the probes, you need to
create a separate "tap set" file (`.stp`); the Solaris/DTrace analogy to this
is called a Provider Support File, I believe. 

**See also:** [System Tap "Adding User Space Probing to an Application"
page](https://sourceware.org/systemtap/wiki/AddingUserSpaceProbingToApps)

LTTng
--------------------------------------------------------------------------------

Skimmed the LTTng documents. It appears to  require multiple daemons, a kernel 
module, and compilation against their library. 

Bibliography
--------------------------------------------------------------------------------

* [1] [DTrace guide](http://dtrace.org/guide/preface.html)
* [2] [Brendan Gregg, "Choosing a Linux Tracer"](http://www.brendangregg.com/blog/2015-07-08/choosing-a-linux-tracer.html)
* [3] [Ftrace Kernel Documentation](https://www.kernel.org/doc/Documentation/trace/ftrace.txt)
* [4] [Kprobe Kernel Documentation](https://www.kernel.org/doc/Documentation/kprobes.txt)
* [5] [Brendan Gregg, "Linux uprobe: User-Level Dynamic Tracing"](http://www.brendangregg.com/blog/2015-06-28/linux-ftrace-uprobe.html)
* [6] [Uprobe Tracer Kernel Documentation](https://www.kernel.org/doc/Documentation/trace/uprobetracer.txt)
* [7] [BCC argdist_example.txt](https://github.com/iovisor/bcc/blob/master/tools/argdist_example.txt)
* [8] [Tracepoints Kernel Documentation](https://www.kernel.org/doc/Documentation/trace/tracepoints.txt)
* [9] [Brendan Gregg, "perf Static Tracepoints"](http://www.brendangregg.com/blog/2014-06-29/perf-static-tracepoints.html)
* [10] [Blogpost on Linux's Static Tracepoints](https://anton.ozlabs.org/blog/2009/10/07/linux-static-tracepoints/)
* [11] [LKML post concerning new BPF backend for SystemTap](https://lkml.org/lkml/2016/6/14/749)
* [12] [System Tap, "Adding User Space Probing to an Application"](https://sourceware.org/systemtap/wiki/AddingUserSpaceProbingToApps)
* [13] [System Tap, "User Space Probe Implementation"](https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation)
* [14] [GDB Static Probe Points Documentation](https://github.com/iovisor/bcc/blob/master/tools/tplist_example.txt)
* [15] [Sasha Goldshtein's post when he added USDT to BCC](http://blogs.microsoft.co.il/sasha/2016/03/30/usdt-probe-support-in-bpfbcc/)
