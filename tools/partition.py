#!/usr/bin/env python
#
# partition.py  Traces the low-level commands of the sharding partition logic. 
#
# Copyright (c) 2016 Memsql, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 8-Aug-2016   Created by Kyle Laracey. Does not work. 

from __future__ import print_function
import argparse
import os
import time
from bcc import BPF, DEBUG_PREPROCESSOR, DEBUG_BPF, USDT

parser = argparse.ArgumentParser(
        description="Trace partition events. "
        "Must be run with root privileges.")
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
#include <linux/blkdev.h>

PROBES
"""

probe_names = [
        "async__create__table__finish__worker",
        "restore__finish__worker",
        "restore__start__worker",
        "repoint__worker",
        "drop__partition__worker",
        "drop__instance__worker",
        "reforge__worker",
        "async__create__table__start__worker",
        "drop__table__worker",
        "failover__worker",
        "create__or__copy__worker"]

probe_text = \
"""
int NAME(struct pt_regs *ctx, int __loc_id)
{
    char *arg1;
    u64 arg2;
    bpf_usdt_readarg(1, ctx, &arg1);
    bpf_usdt_readarg(2, ctx, &arg2);

    bpf_trace_printk("NAME %s:%d\\n", arg1, arg2);

    return 0;
}

"""

probes = {}

all_probes_text = ""
all_thunks_text = ""

u = USDT(path=args.bin_path)
for name in probe_names:
    t = probe_text.replace("NAME", name)
    all_probes_text += t
    u.enable_probe(probe=name, fn_name=name)

replacements = {}

replacements["PROBES"] = all_probes_text

for k, v in replacements.iteritems():
    text=text.replace(k, v)
       
debug = DEBUG_PREPROCESSOR|DEBUG_BPF if args.debug > 1 else 0

b = BPF(text=text, debug=debug, usdt=u)
#for (_, p) in probes.iteritems():
#    p.attach(b, debug=args.debug>0)

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
