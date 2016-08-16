#!/usr/bin/env python
#
# query_latency.py  Traces queries and displays a histogram of their memory 
#                   usage, optionally filtering on a particular plan ID.
#
# Copyright (c) 2016 Memsql, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 29-Jul-2016   Created by Kyle Laracey

from __future__ import print_function
import argparse
import os
import time
from bcc import BPF, DEBUG_PREPROCESSOR, DEBUG_BPF
from bcc.usdt import USDT

parser = argparse.ArgumentParser(description="Trace queries and display a "
        "histogram of their latencies, optionally filtering on a particular "
        "plan ID. Must be run with root privileges.")
parser.add_argument("-p", "--planid", help="the plan id of a query to trace", 
        type=int)
parser.add_argument("bin_path", help="path to the memsqld binary being "
        "instrumented")
parser.add_argument("-d", "--debug", help="print out probe attachment "
        "information; double the flag (-dd) to print out the generated "
        "instrumentation program in C and BPF assembly", action="count")
parser.add_argument("-H", "--histogram", help="display a histogram of "
        "latencies, instead of just printing out each matching query's "
        "latency", action="store_true")
args = parser.parse_args()

# for BPF syscalls
if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.")

text = """
#include <uapi/linux/ptrace.h>

STORAGE
BPF_HASH(start, u32);

int querystart(struct pt_regs *ctx)
{
    s64 arg2;
    bpf_usdt_readarg(4, ctx, &arg2);

    PLANID_FILTER

    u64 start_ts = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    start.lookup_or_init(&pid, &start_ts); 
    return 0;
}

int queryend(struct pt_regs *ctx)
{
    char *arg1;
    bpf_usdt_readarg(1, ctx, &arg1);

    u32 pid = bpf_get_current_pid_tgid();

    u64 *start_ts = start.lookup(&pid);
    if (!start_ts) 
    {
        return 0;
    }

    u64 delta_ms = (bpf_ktime_get_ns() - *start_ts) / 1000 / 1000;
    QUERYEND_COLLECT
    
    start.delete(&pid);
    return 0;
}
"""

u = USDT(path=args.bin_path)
u.enable_probe(probe="query__start", fn_name="querystart")
u.enable_probe(probe="query__done", fn_name="queryend")

replacements = {}

replacements["PLANID_FILTER"] = ""
replacements["STORAGE"] = ""
replacements["QUERYEND_COLLECT"] =  \
    'bpf_trace_printk("%s took %dms\\n", {0}, delta_ms);'.format("arg1")

if args.histogram:
    replacements["STORAGE"] = "BPF_HISTOGRAM(latency);"
    replacements["QUERYEND_COLLECT"] = \
        "latency.increment(bpf_log2l(delta_ms));"

if args.planid is not None:
    replacements["PLANID_FILTER"] = \
            "if (%s != %sULL) return 0;" % ("arg2", args.planid)

for k, v in replacements.iteritems():
    text=text.replace(k, v)
       
debug = DEBUG_PREPROCESSOR|DEBUG_BPF if args.debug>0 else 0

b = BPF(text=text, debug=debug, usdt=u)

if args.planid is not None:
    print("Tracing queries with plan ID %d. ^C to exit." % args.planid)
else:
    print("Tracing queries. ^C to exit.")

try:
    while True:
        if args.histogram:
            print("%-8s\n" % time.strftime("%H:%M:%S"), end="")
            print("latency (ms):")
            b["latency"].print_log2_hist()
            time.sleep(1)
        else: 
            (_, _, _, _, _, msg) = b.trace_fields()
            print("%-8s " % time.strftime("%H:%M:%S"), end="")
            print(msg)


except KeyboardInterrupt:
    pass
