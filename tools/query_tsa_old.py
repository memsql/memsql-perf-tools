#!/usr/bin/env python
#
# query_tsa_old.py  
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
# Important parts of the scheduler cannot be kprobed, and so this script
# attaches kprobes to functions close to there. This is why `query_tsa.py` was
# created; it uses kernel tracepoints, but thus requires kernel version >= 4.7.
# Note that it does not really work.

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
#include <linux/sched.h>
#include <linux/stop_machine.h>

BPF_HASH(tracing, u32); // pid -> startts (also, if this thread is being traced)
BPF_HASH(io, u32);      // pid -> io time
BPF_HASH(sleep, u32);   // pid -> sleep time
BPF_HASH(blocked, u32); // pid -> blocked time
BPF_HASH(wait, u32);    // pid -> wait time (runnable but not running)

// all these are caught by bcc:
// // based on my kernel:
// #define CONFIG_64BIT
// #define CONFIG_CFS_BANDWIDTH
// #define CONFIG_CPU_IDLE
// #define CONFIG_FAIR_GROUP_SCHED
// // CONFIG_IRQ_TIME_ACCOUNTING is not set
// #define CONFIG_NO_HZ_COMMON
// // CONFIG_NO_HZ_FULL is not set
// #define CONFIG_NUMA_BALANCING
// #define CONFIG_PARAVIRT
// // CONFIG_PARAVIRT_TIME_ACCOUNTING is not set
// // CONFIG_RT_GROUP_SCHED is not set
// #define CONFIG_SCHEDSTATS
// #define CONFIG_SCHED_DEBUG
// #define CONFIG_SCHED_HRTICK
// #define CONFIG_SMP

// because CONFIG_IRQ_WORK is defined: (not caught by bcc)
#define HAVE_RT_PUSH_IPI 

struct irq_work {
    unsigned long flags;
    struct llist_node llnode;
    void (*func)(struct irq_work *);
};

/*
 * This is the priority-queue data structure of the RT scheduling class:
 */
struct rt_prio_array {
    DECLARE_BITMAP(bitmap, MAX_RT_PRIO+1); /* include 1 bit for delimiter */
    struct list_head queue[MAX_RT_PRIO];
};

/* Real-Time classes' related field in a runqueue: */
struct rt_rq {
	struct rt_prio_array active;
	unsigned int rt_nr_running;
#if defined CONFIG_SMP || defined CONFIG_RT_GROUP_SCHED
	struct {
		int curr; /* highest queued rt task prio */
#ifdef CONFIG_SMP
		int next; /* next highest */
#endif
	} highest_prio;
#endif
#ifdef CONFIG_SMP
	unsigned long rt_nr_migratory;
	unsigned long rt_nr_total;
	int overloaded;
	struct plist_head pushable_tasks;
#ifdef HAVE_RT_PUSH_IPI
	int push_flags;
	int push_cpu;
	struct irq_work push_work;
	raw_spinlock_t push_lock;
#endif
#endif /* CONFIG_SMP */
	int rt_queued;

	int rt_throttled;
	u64 rt_time;
	u64 rt_runtime;
	/* Nests inside the rq lock: */
	raw_spinlock_t rt_runtime_lock;

#ifdef CONFIG_RT_GROUP_SCHED
	unsigned long rt_nr_boosted;

	struct rq *rq;
	struct task_group *tg;
#endif
};

/* Deadline class' related fields in a runqueue */
struct dl_rq {
	/* runqueue is an rbtree, ordered by deadline */
	struct rb_root rb_root;
	struct rb_node *rb_leftmost;

	unsigned long dl_nr_running;

#ifdef CONFIG_SMP
	/*
	 * Deadline values of the currently executing and the
	 * earliest ready task on this rq. Caching these facilitates
	 * the decision wether or not a ready but not running task
	 * should migrate somewhere else.
	 */
	struct {
		u64 curr;
		u64 next;
	} earliest_dl;

	unsigned long dl_nr_migratory;
	int overloaded;

	/*
	 * Tasks on this rq that can be pushed away. They are kept in
	 * an rb-tree, ordered by tasks' deadlines, with caching
	 * of the leftmost (earliest deadline) element.
	 */
	struct rb_root pushable_dl_tasks_root;
	struct rb_node *pushable_dl_tasks_leftmost;
#else
	struct dl_bw dl_bw;
#endif
};

struct cfs_rq {
	struct load_weight load;
	unsigned int nr_running, h_nr_running;

	u64 exec_clock;
	u64 min_vruntime;
#ifndef CONFIG_64BIT
	u64 min_vruntime_copy;
#endif

	struct rb_root tasks_timeline;
	struct rb_node *rb_leftmost;

	/*
	 * 'curr' points to currently running entity on this cfs_rq.
	 * It is set to NULL otherwise (i.e when none are currently running).
	 */
	struct sched_entity *curr, *next, *last, *skip;

#ifdef	CONFIG_SCHED_DEBUG
	unsigned int nr_spread_over;
#endif

#ifdef CONFIG_SMP
	/*
	 * CFS Load tracking
	 * Under CFS, load is tracked on a per-entity basis and aggregated up.
	 * This allows for the description of both thread and group usage (in
	 * the FAIR_GROUP_SCHED case).
	 * runnable_load_avg is the sum of the load_avg_contrib of the
	 * sched_entities on the rq.
	 * blocked_load_avg is similar to runnable_load_avg except that its
	 * the blocked sched_entities on the rq.
	 * utilization_load_avg is the sum of the average running time of the
	 * sched_entities on the rq.
	 */
	unsigned long runnable_load_avg, blocked_load_avg, utilization_load_avg;
	atomic64_t decay_counter;
	u64 last_decay;
	atomic_long_t removed_load;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* Required to track per-cpu representation of a task_group */
	u32 tg_runnable_contrib;
	unsigned long tg_load_contrib;

	/*
	 *   h_load = weight * f(tg)
	 *
	 * Where f(tg) is the recursive weight fraction assigned to
	 * this group.
	 */
	unsigned long h_load;
	u64 last_h_load_update;
	struct sched_entity *h_load_next;
#endif /* CONFIG_FAIR_GROUP_SCHED */
#endif /* CONFIG_SMP */

#ifdef CONFIG_FAIR_GROUP_SCHED
	struct rq *rq;	/* cpu runqueue to which this cfs_rq is attached */

	/*
	 * leaf cfs_rqs are those that hold tasks (lowest schedulable entity in
	 * a hierarchy). Non-leaf lrqs hold other higher schedulable entities
	 * (like users, containers etc.)
	 *
	 * leaf_cfs_rq_list ties together list of leaf cfs_rq's in a cpu. This
	 * list is used during load balance.
	 */
	int on_list;
	struct list_head leaf_cfs_rq_list;
	struct task_group *tg;	/* group that "owns" this runqueue */

#ifdef CONFIG_CFS_BANDWIDTH
	int runtime_enabled;
	u64 runtime_expires;
	s64 runtime_remaining;

	u64 throttled_clock, throttled_clock_task;
	u64 throttled_clock_task_time;
	int throttled, throttle_count;
	struct list_head throttled_list;
#endif /* CONFIG_CFS_BANDWIDTH */
#endif /* CONFIG_FAIR_GROUP_SCHED */
};

struct rq {
	/* runqueue lock: */
	raw_spinlock_t lock;

	/*
	 * nr_running and cpu_load should be in the same cacheline because
	 * remote CPUs use both these fields when doing load calculation.
	 */
	unsigned int nr_running;
#ifdef CONFIG_NUMA_BALANCING
	unsigned int nr_numa_running;
	unsigned int nr_preferred_running;
#endif
	#define CPU_LOAD_IDX_MAX 5
	unsigned long cpu_load[CPU_LOAD_IDX_MAX];
	unsigned long last_load_update_tick;
#ifdef CONFIG_NO_HZ_COMMON
	u64 nohz_stamp;
	unsigned long nohz_flags;
#endif
#ifdef CONFIG_NO_HZ_FULL
	unsigned long last_sched_tick;
#endif
	/* capture load from *all* tasks on this cpu: */
	struct load_weight load;
	unsigned long nr_load_updates;
	u64 nr_switches;

	struct cfs_rq cfs;
	struct rt_rq rt;
	struct dl_rq dl;

#ifdef CONFIG_FAIR_GROUP_SCHED
	/* list of leaf cfs_rq on this cpu: */
	struct list_head leaf_cfs_rq_list;

	struct sched_avg avg;
#endif /* CONFIG_FAIR_GROUP_SCHED */

	/*
	 * This is part of a global counter where only the total sum
	 * over all CPUs matters. A task can increase this counter on
	 * one CPU and if it got migrated afterwards it may decrease
	 * it on another CPU. Always updated under the runqueue lock:
	 */
	unsigned long nr_uninterruptible;

	struct task_struct *curr, *idle, *stop;
	unsigned long next_balance;
	struct mm_struct *prev_mm;

	unsigned int clock_skip_update;
	u64 clock;
	u64 clock_task;

	atomic_t nr_iowait;

#ifdef CONFIG_SMP
	struct root_domain *rd;
	struct sched_domain *sd;

	unsigned long cpu_capacity;
	unsigned long cpu_capacity_orig;

	unsigned char idle_balance;
	/* For active balancing */
	int post_schedule;
	int active_balance;
	int push_cpu;
	struct cpu_stop_work active_balance_work;
	/* cpu of this runqueue: */
	int cpu;
	int online;

	struct list_head cfs_tasks;

	u64 rt_avg;
	u64 age_stamp;
	u64 idle_stamp;
	u64 avg_idle;

	/* This is used to determine avg_idle's max value */
	u64 max_idle_balance_cost;
#endif

#ifdef CONFIG_IRQ_TIME_ACCOUNTING
	u64 prev_irq_time;
#endif
#ifdef CONFIG_PARAVIRT
	u64 prev_steal_time;
#endif
#ifdef CONFIG_PARAVIRT_TIME_ACCOUNTING
	u64 prev_steal_time_rq;
#endif

	/* calc_load related fields */
	unsigned long calc_load_update;
	long calc_load_active;

#ifdef CONFIG_SCHED_HRTICK
#ifdef CONFIG_SMP
	int hrtick_csd_pending;
	struct call_single_data hrtick_csd;
#endif
	struct hrtimer hrtick_timer;
#endif

#ifdef CONFIG_SCHEDSTATS
	/* latency stats */
	struct sched_info rq_sched_info;
	unsigned long long rq_cpu_time;
	/* could above be rq->cfs_rq.exec_clock + rq->rt_rq.rt_runtime ? */

	/* sys_sched_yield() stats */
	unsigned int yld_count;

	/* schedule() stats */
	unsigned int sched_count;
	unsigned int sched_goidle;

	/* try_to_wake_up() stats */
	unsigned int ttwu_count;
	unsigned int ttwu_local;
#endif

#ifdef CONFIG_SMP
	struct llist_head wake_list;
#endif

#ifdef CONFIG_CPU_IDLE
	/* Must be inspected within a rcu lock section */
	struct cpuidle_state *idle_state;
#endif
};

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

// // unexported from kernel/sched/fair.c
// static inline struct rq *rq_of(struct cfs_rq *cfs_rq)
// {
//     return cfs_rq->rq;
// }
// 
// // unexported from kernel/sched/sched.h
// static inline u64 rq_clock(struct rq *rq)
// {
//     return rq->clock;
// }

#define ENQUEUE_WAKEUP 1   // kernel/sched/sched.h
// for sleep (including io, which is also tracked separately) and blocked
// can't directly trace enqueue_sleeper, so we trace enqueue_entity
int trace_enqueue_entity(struct pt_regs *ctx, struct cfs_rq *cfs_rq, 
    struct sched_entity *se, int flags)
{
    // enqueue_sleeper only fired if we have ENQUEUE_WAKEUP
    if (!(flags & ENQUEUE_WAKEUP))
        return 0;

    u64 res = 0;
    u32 pid = bpf_get_current_pid_tgid();
    // struct sched_entity *sep = 0;
    // if ((res = bpf_probe_read(&sep, sizeof(sep), &se))) {
    //     bpf_trace_printk("bpf_probe_read se failed: %d\\n", res);
    //     return 0;
    // }
    u64 sleep_start = 0;
    if ((res = bpf_probe_read(&sleep_start, sizeof(sleep_start),
            &(se->statistics.sleep_start)))) {
        bpf_trace_printk("bpf_probe_read stat failed: %d\\n", res);
        return 0;
    }

    // bpf_trace_printk("se:          0x%llx\\n", se);
    // bpf_trace_printk("sleep_start: 0x%llu\\n", sleep_start);

    // if (se->statistics.sleep_start) {
    if (sleep_start) {
        // struct cfs_rq *cfs_rqp = 0;
        struct rq *rqp = 0;
        u64 rq_clock = 0;
        register int sp asm ("sp");
        //bpf_trace_printk("sp: 0x%llx\\n", sp);
        //bpf_trace_printk("cfs_rq: 0x%llx, &cfs_rq: 0x%llx\\n", cfs_rq, &cfs_rq);
        //if ((res = bpf_probe_read(&cfs_rqp, sizeof(cfs_rqp), &cfs_rq))) {
        //    bpf_trace_printk("bpf_probe_read 1 failed: %d\\n", res);
        //    return 0;
        //}
        //bpf_trace_printk("bpf_probe_read 1 (after) cfs_rqp=0x%llx\\n", cfs_rqp);
        //volatile struct cfs_rq *cfs_rqp = cfs_rq;
        //bpf_trace_printk("volatile cfs_rqp=0x%llx\\n", cfs_rqp);

        // -1,2,3 gives nothing useful
        // +1 gets 
        // 0xffff8802119f6c00
        // argidst tracing on enqueue_task_fair shows an rq of
        // 0xffff88021fc96d00,
        // 0xffff88021fd96d00
        // 0xffff88021fc16d00
        // 0xffff88021fd16d00
        // 0xffff88021fc96d00
        // +2 gives 0x0
        // +5 gets
        // 0xffff880210c86ad8 off by 0xf010228
        // 0xffff880035b9b6d8
        // 0xffff880210c86ad8
        // 0xffff880035b9b6d8
        // 0xffff880035b9b6d8
        // +4 gets
        // 0xffff88021549b2d8 off by 0xe000000
        // +3 is always 0x1.


        if ((res = bpf_probe_read(&rqp, sizeof(rqp), &(cfs_rq->rq) + 3))) {
            bpf_trace_printk("bpf_probe_read 2 failed: %d\\n", res);
            return 0;
        }
        bpf_trace_printk("bpf_probe_read 2 (after) rqp=0x%llx\\n", rqp);
            
//        // +0,1,2,3 0x0, +3 sometimes -EFAULT
//        if ((res = bpf_probe_read(&rq_clock, sizeof(rq_clock), &(rqp->clock)))) {
//            bpf_trace_printk("bpf_probe_read 3 failed: %d\\n", res);
//            return 0;
//        }
//        //bpf_trace_printk("bpf_probe_read 3 (after) rq_clock=0x%llx\\n", rq_clock);
//
//        // u64 delta = rq_clock - se->statistics.sleep_start;
//        u64 delta = rq_clock - sleep_start;
//
//        if ((s64)delta < 0)
//            delta = 0;
//
//        bpf_trace_printk("delta: %ul\\n", delta);
//        // u64 *io_ns = io.lookup(&pid);
//        // if (io_ns)
//        //     *io_ns += delta;
//        // else
//        //     io.update(&pid, &delta);
    }

    return 0;
}

/*
int update_curr(struct pt_regs *ctx, struct cfs_rq *cfs_rq)
{
    u32 pid = bpf_get_current_pid_tgid();
}
*/

int queryend(struct pt_regs *ctx, int __loc_id)
{
    u32 pid = bpf_get_current_pid_tgid();

    u64 *active = tracing.lookup(&pid);
    if (!active) 
        return 0;

    u64 *io_ns = io.lookup(&pid);
    if (io_ns)
        bpf_trace_printk("queryend: pid:%u, io time: %ul (ns)\\n", pid, *io_ns);
    else
        bpf_trace_printk("queryend: pid:%u, no io time\\n", pid);

    tracing.delete(&pid);
    io.delete(&pid);
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

b.attach_kprobe(event="enqueue_entity", fn_name="trace_enqueue_entity")

if args.planid is not None:
    print("Tracing plan ID %d" % args.planid)

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
