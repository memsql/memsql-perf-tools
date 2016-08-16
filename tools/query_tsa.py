#!/usr/bin/env python
#
# query_tsa.py
#
# Copyright (c) 2016 Memsql, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# The goal of this script is to reveal how much time a particular thread is
# spent in various scheduler states. See tracing-notes.md for what I've learned
# about the scheduler; very useful are the Linux Documentation articles and
# https://tampub.uta.fi/bitstream/handle/10024/96864/GRADU-1428493916.pdf
#
# As of 7/27/16, there is a bug in the BCC Clang rewriter which is supposed to
# allow script writers to elide calls to bpf_read_probe. In order to get as far
# as reading rq_clock, you need to have removed this support from
# b_frontend_action.h's ProbeVisitor::VisitMemberExpr
#
# Reimplementation of query_tsa_old.py using kernel tracepoints (4.7+ only)

from __future__ import print_function
import argparse
import os
import time
from bcc import BPF, DEBUG_PREPROCESSOR, DEBUG_BPF, USDT

parser = argparse.ArgumentParser(
        description="Trace a query's thread states. "
        "Must be run with root privileges.")
parser.add_argument("-p", "--planid", help="the plan ID of the query to trace", 
        type=int)
parser.add_argument("bin_path", help="path to the memsqld binary being "
        "instrumented")
parser.add_argument("-d", "--debug", help="print the instrumentation program "
        "in C and BPF assembly", action="count")
args = parser.parse_args()

# for BPF syscalls
if os.geteuid() != 0:
    exit("You need to have root priviliges to run this script.")

text = """
#include <uapi/linux/ptrace.h>
// #include <linux/sched.h>

BPF_HASH(tracing, u32); // pid -> startts (also, if this thread is being traced)
BPF_HASH(iotime, u32);      // pid -> io time
BPF_HASH(sleeptime, u32);   // pid -> sleep time
BPF_HASH(blockedtime, u32); // pid -> blocked time
BPF_HASH(waittime, u32);// pid -> wait time (runnable but not running)
BPF_HASH(runtime, u32); // pid -> runtime
BPF_HASH(vruntime, u32); // pid -> vruntime

int querystart(struct pt_regs *ctx, int __loc_id)
{
    u64 arg2;
    bpf_usdt_readarg(4, ctx, &arg2);

    PLANID_FILTER

    u32 pid = bpf_get_current_pid_tgid();
    bpf_trace_printk("querystart (pid:%u)\\n", pid);

    u64 startts = bpf_ktime_get_ns();
    tracing.update(&pid, &startts); 
    return 0;
}

struct sched_stat_runtime_args 
{
    // from /sys/kernel/debug/tracing/events/sched/sched_stat_runtime/format
    u64 __unused__;
    char comm[16];
    pid_t pid;
    u64 runtime;
    u64 vruntime;
};

int sched_stat_runtime(struct sched_stat_runtime_args *argsp)
{

    /* common prologue */

    u32 pid = bpf_get_current_pid_tgid();

    u64 *active = tracing.lookup(&pid);
    if (!active) 
        return 0;

    struct sched_stat_runtime_args args = {0};
    u64 res;
    if ((res = bpf_probe_read(&args, sizeof(args), argsp)))
    {
        bpf_trace_printk("sched_stat_runtime failed to read args: %d\\n", res);
        return 0;
    }

    if (args.pid != pid)
    {
        bpf_trace_printk("args.pid=%d, pid=%d\\n", args.pid, pid);
    }

    /* update maps */

    u64 *run = runtime.lookup(&pid);
    if (run) 
    {
        *run += args.runtime;
    }
    else
    {
        runtime.update(&pid, &args.runtime);
    }

    u64 *vrun = vruntime.lookup(&pid);
    if (vrun) 
    {
        *vrun += args.vruntime;
    }
    else
    {
        vruntime.update(&pid, &args.vruntime);
    }

    return 0;
}

struct sched_stat_wait_args 
{
    u64 __unused__;
    char comm[16];
    pid_t pid;
    u64 delay;
};

int sched_stat_wait(struct sched_stat_wait_args *argsp) 
{
    /* common prologue */

    bpf_trace_printk("wait\\n");
//    u32 pid = bpf_get_current_pid_tgid();
//
//    //u64 *active = tracing.lookup(&pid);
//    //if (!active) 
//    //    return 0;
//
//    struct sched_stat_wait_args args = {0};
//    u64 res;
//    if ((res = bpf_probe_read(&args, sizeof(args), argsp)))
//    {
//        bpf_trace_printk("sched_stat_wait failed to read args: %d\\n", res);
//        return 0;
//    }
//
//    bpf_trace_printk("wait: args.pid=%d\\n", args.pid);
//    u64 *active = tracing.lookup(&args.pid);
//    if (!active)
//        return 0;
//
//    /* update maps */
//    u64 *wait = waittime.lookup(&pid);
//    if (wait)
//    {
//        *wait += args.delay;
//    }
//    else
//    {
//        waittime.update(&pid, &args.delay);
//    }
//
    return 0;
}

struct sleep_args
{
   u64 __unused__;
   char comm[16];
   pid_t pid;
   u64 delay;
};

int trace_sleep(struct sleep_args *argsp)
{
    /* common prologue */

    bpf_trace_printk("sleep\\n");
//    u32 pid = bpf_get_current_pid_tgid();
//
//    //u64 *active = tracing.lookup(&pid);
//    //if (!active) 
//    //    return 0;
//
//    struct sleep_args args = {0};
//    u64 res;
//    if ((res = bpf_probe_read(&args, sizeof(args), argsp)))
//    {
//        bpf_trace_printk("trace_sleep failed to read args: %d\\n", res);
//        return 0;
//    }
//
//    bpf_trace_printk("sleep: args.pid=%d\\n", args.pid);
//    u64 *active = tracing.lookup(&args.pid);
//    if (!active)
//        return 0;
//
//    /* update maps */
//
//    u64 *sleep = sleeptime.lookup(&args.pid);
//    if (sleep)
//        *sleep += args.delay;
//    else
//        sleeptime.update(&args.pid, &args.delay);
//
    return 0;
}

struct blocked_args
{
   u64 __unused__;
   char comm[16];
   pid_t pid;
   u64 delay;
};

int trace_blocked(struct blocked_args *argsp)
{
    /* common prologue */

    bpf_trace_printk("blocked\\n");
//    u32 pid = bpf_get_current_pid_tgid();
//
//    //u64 *active = tracing.lookup(&pid);
//    //if (!active) 
//    //    return 0;
//
//    struct blocked_args args = {0};
//    u64 res;
//    if ((res = bpf_probe_read(&args, sizeof(args), argsp)))
//    {
//        bpf_trace_printk("trace_blocked failed to read args: %d\\n", res);
//        return 0;
//    }
//
//    bpf_trace_printk("blocked: args.pid=%d\\n", args.pid);
//    u64 *active = tracing.lookup(&args.pid);
//    if (!active)
//        return 0;
//
//    /* update maps */
//
//    u64 *blocked = blockedtime.lookup(&args.pid);
//    if (blocked)
//        *blocked += args.delay;
//    else
//        blockedtime.update(&args.pid, &args.delay);
//
    return 0;
}

struct io_args
{
   u64 __unused__;
   char comm[16];
   pid_t pid;
   u64 delay;
};

int trace_io(struct io_args *argsp)
{
    /* common prologue */

    bpf_trace_printk("io\\n");
//    u32 pid = bpf_get_current_pid_tgid();
//
//    //u64 *active = tracing.lookup(&pid);
//    //if (!active) 
//    //    return 0;
//
//    struct io_args args = {0};
//    u64 res;
//    if ((res = bpf_probe_read(&args, sizeof(args), argsp)))
//    {
//        bpf_trace_printk("trace_io failed to read args: %d\\n", res);
//        return 0;
//    }
//
//    bpf_trace_printk("io: args.pid=%d\\n", args.pid);
//    u64 *active = tracing.lookup(&args.pid);
//    if (!active)
//        return 0;
//
//    /* update maps */
//
//    u64 *io = iotime.lookup(&args.pid);
//    if (io)
//        *io += args.delay;
//    else
//        iotime.update(&args.pid, &args.delay);
//
    return 0;
}

int queryend(struct pt_regs *ctx, int __loc_id)
{

    u32 pid = bpf_get_current_pid_tgid();

    u64 *active = tracing.lookup(&pid);
    if (!active) 
        return 0;

    u64 *wait = waittime.lookup(&pid);
    if (wait)
        bpf_trace_printk("queryend: pid:%u, wait time: %lu (ns)\\n", pid, *wait);
    else
        bpf_trace_printk("queryend: pid:%u, no wait time\\n", pid);

    u64 *run = runtime.lookup(&pid);
    if (run)
        bpf_trace_printk("queryend: pid:%u, run time: %lu (ns)\\n", pid, *run);
    else
        bpf_trace_printk("queryend: pid:%u, no run time\\n", pid);

    u64 *vrun = vruntime.lookup(&pid);
    if (vrun)
        bpf_trace_printk("queryend: pid:%u, vrun time: %lu (ns)\\n", pid, *vrun);
    else
        bpf_trace_printk("queryend: pid:%u, no vrun time\\n", pid);

    u64 *sleep = sleeptime.lookup(&pid);
    if (sleep)
        bpf_trace_printk("queryend: pid:%u, sleep time: %lu (ns)\\n", pid, *sleep);
    else
        bpf_trace_printk("queryend: pid:%u, no sleep time\\n", pid);

    u64 *io = iotime.lookup(&pid);
    if (io)
        bpf_trace_printk("queryend: pid:%u, io time: %lu (ns)\\n", pid, *io);
    else
        bpf_trace_printk("queryend: pid:%u, no io time\\n", pid);

    u64 *blocked = blockedtime.lookup(&pid);
    if (blocked)
        bpf_trace_printk("queryend: pid:%u, blocked time: %lu (ns)\\n", pid, *blocked);
    else
        bpf_trace_printk("queryend: pid:%u, no blocked time\\n", pid);

    tracing.delete(&pid);
    waittime.delete(&pid);
    runtime.delete(&pid);
    vruntime.delete(&pid);
    sleeptime.delete(&pid);
    iotime.delete(&pid);
    blockedtime.delete(&pid);
    return 0;
}

int trace_update_stats_wait_end(struct pt_regs *regs)
{
    bpf_trace_printk("update_stats_wait_end\\n");
    return 0;
}
"""

u = USDT(path=args.bin_path)
u.enable_probe(probe="query__start", fn_name="querystart")
u.enable_probe(probe="query__done", fn_name="queryend")

replacements = {}

replacements["PLANID_FILTER"] = ""

if args.planid is not None:
    replacements["PLANID_FILTER"] = \
            "if (%s != %sULL) return 0;" % ("arg2", args.planid)

for k, v in replacements.iteritems():
    text=text.replace(k, v)
       
debug = DEBUG_PREPROCESSOR|DEBUG_BPF if args.debug > 1 else 0

b = BPF(text=text, debug=debug, usdt=u)

b.attach_tracepoint("sched:sched_stat_wait", "sched_stat_wait")
b.attach_tracepoint("sched:sched_stat_runtime", "sched_stat_runtime")
b.attach_tracepoint("sched:sched_stat_sleep", "trace_sleep")
b.attach_tracepoint("sched:sched_stat_blocked", "trace_blocked")
b.attach_tracepoint("sched:sched_stat_iowait", "trace_io")

if args.planid is not None:
    print("Tracing plan ID %d... ^C to exit" % args.planid)
else:
    print("Tracing... ^C to exit")

try:
    while True:
        #print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
        #print("number of pagefaults")
        #b["pagefaults"].print_log2_hist()
        #time.sleep(1)
        (_, _, _, _, _, msg) = b.trace_fields()
        print("%-8s " % time.strftime("%H:%M:%S"), end="")
        print(msg)


except KeyboardInterrupt:
    pass
