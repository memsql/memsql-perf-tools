#!/usr/bin/env python
#
# query_memory.py   Traces a query and displays a histogram of its memory usage,
#                   optionally filtering on plan ID.
#
# Copyright (c) 2016 Memsql, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 29-Jul-2016  Created by Kyle Laracey

from __future__ import print_function
import argparse
import os
import time
from bcc import BPF, DEBUG_PREPROCESSOR, DEBUG_BPF, USDT

parser = argparse.ArgumentParser(description="Trace queries and display a "
        "histogram of their memory usage, optionally filtering on a particular "
        "plan ID. Must be run with root privileges.")
parser.add_argument("-p", "--planid", help="the plan ID of the query to trace", 
        type=int)
parser.add_argument("bin_path", help="path to the memsqld binary being "
        "instrumented")
parser.add_argument("-d", "--debug", help="print out probe attachment "
        "information; double the flag (-dd) to print out the generated "
        "instrumentation program in C and BPF assembly", action="count")
parser.add_argument("-H", "--histogram", help="display a histogram of "
        "memory usage", action="store_true")
args = parser.parse_args()

# for BPF syscalls
if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.")

text = """
#include <uapi/linux/ptrace.h>

STORAGE
BPF_HASH(tracing, u32); // pid -> whether we are tracing
BPF_HASH(memory, u32);  // pid -> memory used

int querystart(struct pt_regs *ctx)
{
    u64 arg2;
    bpf_usdt_readarg(4, ctx, &arg2);

    PLANID_FILTER

    u64 start_ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    tracing.lookup_or_init(&pid, &start_ts); 
    return 0;
} 

int execstats_addmemoryuse(struct pt_regs *ctx) 
{
    u64 delta_bytes = 0;
    bpf_usdt_readarg(1, ctx, &delta_bytes);

    u32 pid = bpf_get_current_pid_tgid();

    // is this thread executing a query we care about?
    if (!tracing.lookup(&pid)) 
    {
        return 0;
    }

    u64 *mem = memory.lookup(&pid);
    if (mem) 
    {
        (*mem) += delta_bytes;
    } 
    else
    {
        memory.update(&pid, &delta_bytes);
    }

    return 0;
}

int queryend(struct pt_regs *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();

    u64 *start_ts = tracing.lookup(&pid);
    if (!start_ts) 
    {
        return 0;
    }

    QUERYEND_COLLECT
    tracing.delete(&pid);
    memory.delete(&pid);
    return 0;
}
"""

u = USDT(path=args.bin_path)
u.enable_probe(probe="query__start", fn_name="querystart")
u.enable_probe(probe="execstats__addmemoryuse", fn_name="execstats_addmemoryuse")
u.enable_probe(probe="query__done", fn_name="queryend")

replacements = {}

replacements["PLANID_FILTER"] = ""
replacements["STORAGE"] = ""
replacements["QUERYEND_COLLECT"] = \
"""
u64 *mem = memory.lookup(&pid);
if (mem)
{
    bpf_trace_printk("query used: %d bytes\\n", *mem);
}
"""

if args.histogram:
    replacements["STORAGE"] = "BPF_HISTOGRAM(mem_hist);"
    replacements["QUERYEND_COLLECT"] = \
"""
u64 *mem = memory.lookup(&pid);
if (mem)
{
    mem_hist.increment(bpf_log2l(*mem));
}
"""

if args.planid is not None:
    replacements["PLANID_FILTER"] = \
            "if (%s != %sULL) return 0;" % ("arg2", args.planid)

for k, v in replacements.iteritems():
    text=text.replace(k, v)
       
debug = DEBUG_PREPROCESSOR|DEBUG_BPF if args.debug > 0 else 0

b = BPF(text=text, debug=debug, usdt=u)

if args.planid is not None:
    print("Tracing memory usage of queries with plan ID %d. Press ^C to stop" 
            % args.planid)
else:
    print("Tracing memory usage of queries. Press ^C to stop.")

try:
    while True:
        if args.histogram:
            print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
            print("memory usage (bytes):")
            b["mem_hist"].print_log2_hist()
            time.sleep(1)
        else: 
            (_, _, _, _, _, msg) = b.trace_fields()
            print("%-8s " % time.strftime("%H:%M:%S"), end="")
            print(msg)

except KeyboardInterrupt:
    pass
