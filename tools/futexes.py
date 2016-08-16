#!/usr/bin/env python
#
# futexes.py    Trace futex syscalls.
#
# Copyright (c) 2016 Memsql, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 29-July-2016  Created by Kyle Laracey

from __future__ import print_function
import argparse, time, os 
from bcc import BPF, DEBUG_PREPROCESSOR, DEBUG_BPF, USDT 

parser = argparse.ArgumentParser(description="Trace futex system calls, "
        "optionally filtering by process ID or query plan ID. Must be run with "
        "root privileges")
parser.add_argument("-p", "--planid", help="the plan ID of the query to trace", 
        type=int)
parser.add_argument("bin_path", help="path to the memsqld binary being "
        "instrumented")
parser.add_argument("-d", "--debug", help="print out probe attachment "
        "information; double the flag (-dd) to print out the generated "
        "instrumentation program in C and BPF assembly", action="count")
parser.add_argument("-P", "--process", help="filter by process ID (TGID)",
        type=int)
parser.add_argument("-H", "--histogram", help="display a histogram of the "
        "data.", action="store_true")
args = parser.parse_args()

if args.process and args.planid:
    exit("You cannot filter by both process and planid.")

# for BPF syscalls
if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.")

text="""
#include <uapi/linux/ptrace.h>
#include <linux/ktime.h>

BPF_HASH(tracing, u32);
BPF_HASH(start, u32); // pid -> futex call start timestamp
STORAGE

// u32 val3 dropped because bcc only supports so many parameters, and only in
// registers
int trace_futex(struct pt_regs *ctx, u32 __user *uaddr, int op, u32 val, ktime_t
    *timeout, u32 __user *uaddr2, u32 val2)
{
    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = tgid_pid;
    u32 tgid = tgid_pid >> 32;

    FUTEX_FILTER
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int trace_futex_return(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();

    u64 *startts = start.lookup(&pid);
    if (!startts)   // not tracing or missed futex start
        return 0;

    u64 delta = (bpf_ktime_get_ns() - *startts)/1000/1000;
    FUTEX_COLLECT

    start.delete(&pid);
    return 0;
}

QUERYTEXT
"""

replacements = {}
replacements["STORAGE"] = ""
replacements["FUTEX_FILTER"] = ""
replacements["QUERYTEXT"] = ""
replacements["FUTEX_COLLECT"] = \
        'bpf_trace_printk("futex took %d ms\\n", delta);'
if args.histogram:
    replacements["STORAGE"] = "BPF_HISTOGRAM(hist);"
    replacements["FUTEX_COLLECT"] = "hist.increment(bpf_log2l(delta));"

if args.process is not None:
    replacements["FUTEX_FILTER"] = "if (tgid != %s) return 0;" % args.process

if args.planid is not None:
    querytext = \
"""
int querystart(struct pt_regs *ctx, int __loc_id)
{
    u64 planid;
    bpf_usdt_readarg(4, ctx, &planid);

    PLANID_FILTER

    u32 pid = bpf_get_current_pid_tgid();
    u64 true = 1;
    tracing.update(&pid, &true); 
    return 0;
}

int queryend(struct pt_regs *ctx, int __loc_id)
{
    u32 pid = bpf_get_current_pid_tgid();

    if (!tracing.lookup(&pid)) return 0;

    u64 *dur = duration.lookup(&pid);
    QUERYEND_COLLECT

    tracing.delete(&pid);
    return 0;
}
"""
    replacements["PLANID_FILTER"] = \
            "if (%s != %sULL) return 0;" % ("planid", args.planid)
    replacements["FUTEX_FILTER"] = " if (!tracing.lookup(&pid)) return 0;"
    replacements["STORAGE"] += "\nBPF_HISTOGRAM(duration, u32);"
    replacements["FUTEX_COLLECT"] = \
"""
    u64 *dur = duration.lookup(&pid);
    if (dur)
        *dur += delta;
    else 
        duration.update(&pid, &delta);
"""
    u = USDT(path=args.bin_path)
    u.enable_probe(probe="query__start", fn_name="querystart")
    u.enable_probe(probe="query__done", fn_name="queryend")
    if args.histogram:
        replacements["QUERYEND_COLLECT"] = \
            "if (dur) hist.increment(bpf_log2l(*dur));"
    else:
        replacements["QUERYEND_COLLECT"] = \
"""
    if (dur)
        bpf_trace_printk("query spent %d ms in futex\\n", *dur);
    else 
        bpf_trace_printk("query spent no time in futex\\n");
"""
    
    for k, v in replacements.iteritems():
        querytext=querytext.replace(k, v)

    replacements["QUERYTEXT"] = querytext

for k, v in replacements.iteritems():
    text=text.replace(k, v)

debug = DEBUG_PREPROCESSOR|DEBUG_BPF if args.debug>1 else 0
usdt = u if args.planid is not None else None
b = BPF(text=text, debug=debug, usdt=usdt)
b.attach_kprobe("do_futex", "trace_futex")
b.attach_kretprobe("do_futex", "trace_futex_return")
#b.attach_tracepoint("syscalls:sys_enter_futex", "trace_futex")
#b.attach_tracepoint("syscalls:sys_exit_futex", "trace_futex_return")

if args.planid is not None:
    print("Tracing futexes during queries with plan ID %d. Press ^C to stop."
            % args.planid)
elif args.process is not None:
    print("Tracing futexes in process %d. Press ^C to stop." % args.process)
else:
    print("Tracing futexes globally. Press ^C to stop.")

try:
    while True:
        if args.histogram:
            print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
            print("futex latencies (ms):")
            b["hist"].print_log2_hist()
            time.sleep(1)
        else:
            (_, _, _, _, _, msg) = b.trace_fields()
            print("%-8s " % time.strftime("%H:%M:%S"), end="")
            print(msg)

except KeyboardInterrupt:
    pass
