#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# query_bio   Trace block device I/O and print details including issuing PID, 
#             optionally filtering on plan ID. Derived from bcc/biosnoop.py
#
# This uses in-kernel eBPF maps to cache process details (PID and comm) by I/O
# request, as well as a starting timestamp for calculating I/O latency. As of
# 8/11/2016, it does not work. 
#
# Copyright (c) 2016 Memsql, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# This script is derived from Brendan Gregg and Allan McAleavy's BCC script 
# biosnoop.py.  The original code is available from:
#     https://github.com/iovisor/bcc/blob/master/tools/biosnoop.py

from __future__ import print_function
from bcc import BPF, USDT
import ctypes as ct
import re
import argparse
import os

parser = argparse.ArgumentParser(
        description="Trace a query and it's block I/O. "
        "Must be run with root privileges.")
parser.add_argument("-p", "--pids", help="the process IDs to trace")
parser.add_argument("bin_path", help="path to the memsqld binary being "
        "instrumented")
parser.add_argument("-d", "--debug", help="print the instrumentation program "
        "in C and BPF assembly", action="count")
args = parser.parse_args()

# for BPF syscalls
if os.geteuid() != 0:
    exit("You need to have root priviliges to run this script.")

try:
    tgids = map(int, args.pids.split(","))
except ValueError:
    exit("Process IDs not valid numbers")

# load BPF program
text="""
#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

struct val_t {
    u32 pid;
    char name[TASK_COMM_LEN];
};

struct data_t {
    u32 pid;
    u64 rwflag;
    u64 delta;
    u64 sector;
    u64 len;
    u64 ts;
    char disk_name[DISK_NAME_LEN];
    char name[TASK_COMM_LEN];
};

BPF_HASH(start, struct request *);
BPF_HASH(infobyreq, struct request *, struct val_t);
BPF_PERF_OUTPUT(events);
BPF_HASH(tracing, u32);

// cache PID and comm by-req
int trace_pid_start(struct pt_regs *ctx, struct request *req)
{
    struct val_t val = {};

    // u32 pid = bpf_get_current_pid_tgid();
    // u64 *active = tracing.lookup(&pid);
    // if (!active) 
    // {
    //     return 0;
    // }

    u64 tgid = bpf_get_current_pid_tgid();
    tgid >>= 32;



    if (bpf_get_current_comm(&val.name, sizeof(val.name)) == 0) {
        val.pid = pid;
        infobyreq.update(&req, &val);
    }
    return 0;
}

// time block I/O
int trace_req_start(struct pt_regs *ctx, struct request *req)
{
    u64 ts;

    ts = bpf_ktime_get_ns();
    start.update(&req, &ts);

    return 0;
}

// output
int trace_req_completion(struct pt_regs *ctx, struct request *req)
{
    u64 *tsp, delta;
    u32 *pidp = 0;
    struct val_t *valp;
    struct data_t data ={};
    u64 ts;

    // fetch timestamp and calculate delta
    tsp = start.lookup(&req);
    if (tsp == 0) {
        // missed tracing issue
        return 0;
    }
    ts =  bpf_ktime_get_ns();
    data.delta = ts - *tsp;
    data.ts = ts / 1000;

    valp = infobyreq.lookup(&req);
    if (valp == 0) {
        start.delete(&req);
        return 0;
        // data.len = req->__data_len;
        //strcpy(data.name,"?");
    } else {
        data.pid = valp->pid;
        u64 *active = tracing.lookup(&data.pid);
        if (!active)
        {
            return 0;
        }
        data.len = req->__data_len;
        data.sector = req->__sector;
        bpf_probe_read(&data.name, sizeof(data.name), valp->name);
        bpf_probe_read(&data.disk_name, sizeof(data.disk_name),
                       req->rq_disk->disk_name);
    }

    if (req->cmd_flags & REQ_WRITE) {
        data.rwflag=1;
    } else {
        data.rwflag=0;
    }
    events.perf_submit(ctx,&data,sizeof(data));
    start.delete(&req);
    infobyreq.delete(&req);

    return 0;
}

int querystart(struct pt_regs *ctx, int __loc_id)
{
    u64 arg2;
    bpf_usdt_readarg(4, ctx, &arg2);

    PLANID_FILTER

    u64 tgid_pid = bpf_get_current_pid_tgid();
    u32 pid = tgid_pid;
    u32 tgid = tgid_pid >> 32;
    bpf_trace_printk("querystart (pid:%u, tgid:%u)\\n", pid, tgid);

    u64 one = 1;
    tracing.update(&pid, &one); 
    bpf_trace_printk("querystart\\n");
    return 0;
}

int queryend(struct pt_regs *ctx, int __loc_id)
{
    u32 pid = bpf_get_current_pid_tgid();

    u64 *active = tracing.lookup(&pid);
    if (!active) 
    {
        return 0;
    }

    bpf_trace_printk("queryend\\n");

    // u32 *bytesp = io.lookup(&pid);
    // if (bytesp)
    // {
    //     bpf_trace_printk("queryend: pid:%u, i/o bytes: %5ul\\n", pid, *bytesp);
    // }
    // else
    // {
    //     bpf_trace_printk("queryend: pid:%u, no block I/O\\n", pid);
    // }

    tracing.delete(&pid);
    // io.delete(&pid);
    return 0;
}
"""

#replacements = {}
#
#replacements["PLANID_FILTER"] = ""
#
#if args.planid is not None:
#    replacements["PLANID_FILTER"] = \
#            "if (%s != %sULL) return 0;" % ("arg2", args.planid)
#
# u = USDT(path=args.bin_path)
# u.enable_probe(probe="query__start", fn_name="querystart")
# u.enable_probe(probe="query__done", fn_name="queryend")

#for k, v in replacements.iteritems():
#    text=text.replace(k, v)

#b = BPF(text=text, debug=0, usdt=u)
b = BPF(text=text)

b.attach_kprobe(event="blk_account_io_start", fn_name="trace_pid_start")
b.attach_kprobe(event="blk_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_mq_start_request", fn_name="trace_req_start")
b.attach_kprobe(event="blk_account_io_completion",
    fn_name="trace_req_completion")

TASK_COMM_LEN = 16  # linux/sched.h
DISK_NAME_LEN = 32  # linux/genhd.h

class Data(ct.Structure):
    _fields_ = [
        ("pid", ct.c_ulonglong),
        ("rwflag", ct.c_ulonglong),
        ("delta", ct.c_ulonglong),
        ("sector", ct.c_ulonglong),
        ("len", ct.c_ulonglong),
        ("ts", ct.c_ulonglong),
        ("disk_name", ct.c_char * DISK_NAME_LEN),
        ("name", ct.c_char * TASK_COMM_LEN)
    ]
# header
print("%-14s %-14s %-6s %-7s %-2s %-9s %-7s %7s" % ("TIME(s)", "COMM", "PID",
    "DISK", "T", "SECTOR", "BYTES", "LAT(ms)"))

rwflg = ""
start_ts = 0
prev_ts = 0
delta = 0

# process event
def print_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data)).contents

    val = -1
    global start_ts
    global prev_ts
    global delta

    if event.rwflag == 1:
        rwflg = "W"

    if event.rwflag == 0:
        rwflg = "R"

    if not re.match(b'\?', event.name):
        val = event.sector

    if start_ts == 0:
        prev_ts = start_ts

    if start_ts == 1:
        delta = float(delta) + (event.ts - prev_ts)

    print("%-14.9f %-14.14s %-6s %-7s %-2s %-9s %-7s %7.2f" % (
        delta / 1000000, event.name, event.pid, event.disk_name, rwflg, val,
        event.len, float(event.delta) / 1000000))

    prev_ts = event.ts
    start_ts = 1

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    b.kprobe_poll()
