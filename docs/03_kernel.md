Kernel Documentation for Writing BPF Scripts
================================================================================

Here are some notes on the kernel with regards to tracing. Currently, there are
only my notes on the scheduler and some info on locks. They are derived from the
4.7 sources.

Scheduler
--------------------------------------------------------------------------------

This section concerns the Completely Fair Scheduler (CFS) structure in 4.7.  A
`sched_entity` or scheduler entity is a unit of scheduling which can be larger
than a task; for instance, it may make sense to group together a group of tasks
which are part of a compilation process, or all the processes of a single user.
This is accomplished by the `sched_entity` abstraction. 

A `sched_entity` can also simply wrap a single task: see 
`fair.c:entity_is_task(se)` which just checks if the `sched_entity` has a `rq`. 

`sched_entity` has a field *`prev_sum_exec_runtime`*: "used for storing the 
previous run time of a process.  When it is taken off the CPU, 
*`sum_exec_runtime`* is copied into this variable. The information will be later
used by the scheduler. Note, that `sum_exec_runtime` is not reset." [1].

### Important Function Pointers in the Sched Class Struct

`kernel/sched/fair.c` defines `fair_sched_class` with all the high-level
important function pointers. Ishkov's [1] definitions are taken from [2]. 

function          | purpose
:----------------  |:----------------
*`enqueue_task`*: | "called when a task enters a runnable state. It puts the scheduling entity (task) into the run queue and increments the nr_running (number of runnable processes in a run queue) variable" 
*`dequeue_task`*: | "when a task is no longer runnable, this function is called to keep the corresponding scheduling entity out of the run queue. It also decrements the nr_running variable" 
*`yield_task`*: | "called when a task wants to voluntarily give up CPU, but not going out of runnable state. Basically this means a dequeue followed by an enqueue" 
*`check_preempt_curr`*: | "this function checks if a task that entered runnable state should preempt the currently running task. Called, for example, from `wake_up_new_task(...)`" 
*`put_prev_task`*: | currently running task returned to the scheduler, in CFS, to the rb tree [3]. "Note, that this is not the same as enqueuing and dequeuing tasks" 
*`pick_next_task`*: | used by `schedule()` to determine the next task to run [3].
*`set_curr_task`*: | this function is called when a task changes its scheduling class or task group 
*`task_tick`*: | "mostly called from time tick functions; it might lead to process switch. This drives the running preemption" 

### Important perf sched events (and their locations):

 event | location  
:------|:--------
`sched:sched_stat_blocked`    | (`enqueue_sleeper`, in the block branch)
`sched:sched_stat_iowait`     | (`enqueue_sleeper`, in the block & iowait branch)
`sched:sched_stat_runtime`    | (`update_curr`, if the `sched_entity` is a task)
`sched:sched_stat_sleep`      | (`enqueue_sleeper`, in the sleep branch)
`sched:sched_stat_wait`       | (`update_stats_wait_end`, if `se` is a task)
`sched:sched_switch`          | (`prepare_switch`, called from context_switch)
`sched:sched_wait_task`       | (`wait_task_inactive`)
`sched:sched_wakeup`          | (`ttwu_do_wakup`)
`sched:sched_waking`          | <appears to be missing>

### Details on important functions

#### `enqueue_sleeper`

Tracepoints: `sched_stat_blocked`, `sched_stat_iowait`, `sched_stat_sleep`

Called by `enqueue_task_fair` which, as mentioned above, "is called whena  task
enters a runnable state."

Call stack:

    unthrottle_cfs_rq AND enqueue_task_fair
    enqueue_entity(cfs_rq, se, flags)
    if (flags & ENQUEUE_WAKER) enqueue_sleeper(cfs_rq, se) 

`unthrottle_cfs_rq` has multiple callsites; `enquque_task_fair` is
`enqueue_task` in the fair `sched_class`.

From the tracepoint event declarations:

  * sleep: "Tracepoint for account sleep time (time the task is not runnable,
    including iowait)"

  * iowait: "time the task is not runnable, due to waiting on IO to complete"
  
  * blocked: "time the task is in uninterruptible" "Uninterruptable processes
    are USUALLY waiting for I/O following a page fault" [4].


#### `update_curr`

Tracepoints: `sched_stat_runtime(curtask, delta_exec, curr_vruntime)`

"Tracepoint for accounting runtime (time the task is executing on a CPU)."
Taken from the event class declaration (`include/trace/events/sched.h:371`).
Supposedly, `runtime` (AKA `delta_exec`) and `vruntime` are both measured in
"ns". (from event declaration)

#### `update_stats_wait_end`

Tracepoints: `sched_stat_wait(task, delay)`

Call stacks:

    dequeue_task_fair AND throttle_cfs_rq   # no longer runnable, or throttle?
    dequeue_entity
    update_stats_dequeue(cfs_rq, se) 
    update_stats_wait_end(cfs_rq, se)

    pick_next_task_fair AND set_curr_task_fair  # about to run, or change class
    set_next_entity(cfs_rq, se)
    update_stats_wait_end(cfs_rq, se)

There is a comment in `set_next_entity` before calling `update_stats_wait_end`:
"Any task has to be enqueued before it get to execute on a CPU. So account for 
the time it spent waiting on the runqueue."

From the event declaration: "Tracepoint for accounting wait time (time the task
is runnable but not actually running due to scheduler contention)".

So it sounds like 'wait' is the same as 'runnable'. 

#### `prepare_task_switch`

Tracepoints: `sched_switch`

Call stack:

    schedule AND preempt_schedule_{common,context,irq}
    __schedule
    context_switch
    prepare_task_switch(rq, task_struct *prev, *next)

*MAKE SURE YOUR KERNEL HAS CONFIG_SCHEDSTATS set. My 4.4 did, but not 4.7.*

### Relevant Kernel Sources
* [`include/linux/sched.h`](http://lxr.free-electrons.com/source/include/linux/sched.h?v=4.7)
* [`kernel/sched/sched.h`](http://lxr.free-electrons.com/source/kernel/sched/sched.h?v=4.7)
* [`kernel/sched/fair.c`](http://lxr.free-electrons.com/source/kernel/sched/fair.c?v=4.7)
* [`kernel/sched/core.c`](http://lxr.free-electrons.com/source/kernel/sched/core.c?v=4.7)

Locking
--------------------------------------------------------------------------------

I did some research on kernel locks to see if we could instrument them.
Unfortunately, it appears all the functions that operate on them are inlined.
There might be tracepoints (in addition to the file lock tracepoint referenced
below) that we could use though.

Here is a list of the important lock functions:

    rw_semaphore (rwsem_*)
        funcs (from i/l/rwsem.h):
            rwsem_down_read_failed
            rwsem_down_write_failed
            rwsem_wake
            rwsem_downgrade_wake
            down
            down_read
            down_read_trylock
            down_write
            up_read
            up_write
            downgrade_write
            down_read_nested        #
            down_write_nested       # unclear
            _down_write_nest_lock   #
        include/linux/rwsem.h
    semaphore 
        funcs (from i/l/semaphore.h):
            down
            down_interruptible
            down_killable
            down_trylock
            down_timeout
            up
        include/linux/semaphore.h
        kernel/locking/semaphore.c
    file_lock (many funcs; not super interesting)
        include/linux/fs.h
    mutexes  
        funcs (from mutex-design.txt):
            mutex_lock
            mutex_lock_nested
            mutex_trylock
            mutex_lock_interruptible_nested
            mutex_lock_interruptible
            atomic_dec_and_mutex_lock
            mutex_unlock
        include/linux/mutex.h
        kernel/locking/mutex.c
        Documentation/locking/mutex-design.txt
    rwlock_t (spinlocks)
        it looks like this is acted on by the `__raw_[spin|read|write}_*` funcs
        funcs (k/l/spinlock.c):
            _raw_spin_trylock
            _raw_spin_trylock_bh
            _raw_spin_lock
            _raw_spin_lock_irqsave
            _raw_spin_lock_bh
            _raw_spin_unlock
            _raw_spin_unlock_irqrestore
            _raw_spin_unlock_irq
            _raw_spin_unlock_bh

            _raw_read_trylock
            _raw_read_lock
            _raw_read_lock_irq
            _raw_read_lock_bh
            _raw_read_unlock
            _raw_read_unlock_irqrestore
            _raw_read_unlock_irq

            _raw_write_trylock
            _raw_write_lock
            _raw_write_lock_irqsave
            _raw_write_lock_irq
            _raw_write_lock_bh
            _raw_write_unlock
            _raw_write_unlock_irqrestore
            _raw_write_unlock_irq
            _raw_write_unlock_bh
    
            _raw_spin_lock_nested
            _raw_spin_lock_bh_nested
            _raw_spin_lock_irqsave_nested
            _raw_spin_lock_nest_lock

        funcs (i/l/spinlock.h):
            do_raw_spin*
            spin_lock
            spin_lock_bh
            spin_trylock
            spin_lock_nested -> raw_spin_lock_nested
            spin_lock_bh_nested -> raw_spin_lock_bh_nested
            spin_lock_nest_lock -> raw_spin_lock_nest_lock
            spin_lock_irq 
            spin_lock_irqsave -> raw_spin_lock_irqsave_nested
            spin_lock_irqsave_nested -> raw_spin_lock_irqsave_nested
            spin_unlock
            spin_unlock_bh
            spin_unlock_irq
            spin_unlock_irqrestore
            spin_trylock_bh
            spin_trylock_irq
            spin_trylock_irqsave
            spin_unlock_wait
            spin_is_locked
            spin_is_contended
            spin_can_lock

        files:
            asm/spinlock_types.h
            asm/spinlock.h
            include/linux/spinlock_types.h
            include/linux/spinlock_api_smp.h
            include/linux/spinlock.h
            include/linux/rwlock.h
            include/linux/rwlock_types.h
            include/linux/rwlock_api_smp.h
                "spinlock API declarations on SMP (implemented in
                 kernel/spinlock.c)"

    raw_spinlock_t, spinlock_t (raw + cache padding + lockdep)
        include/linux/spinlock_types.h
    mcs_spinlock (mcs_spin_(un)lock)
        kernel/locking/mcs_spinlock.h
    struct lockref (lockref_{get,put,mark_dead}*)
        include/linux/lockref.h
    struct kref (kref_*) (though it looks like its all atomic)
        include/linux/kref.h
    futex (futex_wake, do_futex)

It also looks like there are tracepoints for filelock, but nothing else. 

Note that you may be tempted to trace on `lock_acquire`, but that is a lockdep
function [5] which I don't think is what we want. 

### See Also:
* https://events.linuxfoundation.org/sites/events/files/slides/linuxcon-2014-locking-final.pdf
* http://www.linuxgrill.com/anonymous/fire/netfilter/kernel-hacking-HOWTO-5.html

NB: Semaphore can only be used in [user context]
(http://www.linuxgrill.com/anonymous/fire/netfilter/kernel-hacking-HOWTO-2.html), 
because they sleep, which makes sense. 

Bibliography
--------------------------------------------------------------------------------

* [1] [Nikita Ishkov, "A Complete Guide to Linux Scheduling"](https://tampub.uta.fi/bitstream/handle/10024/96864/GRADU-1428493916.pdf?sequence=1)
* [2] [Completely Fair Scheduler Design, Kernel Documentation](https://www.kernel.org/doc/Documentation/scheduler/sched-design-CFS.txt)
* [3] [IBM Developerworks page on CFS](http://www.ibm.com/developerworks/library/l-completely-fair-scheduler/)
* [4] [LKML post concerning new BPF backend for SystemTap](https://lkml.org/lkml/2016/6/14/749)
* [5] [Lockdep Design, Kernel Documentation](https://www.kernel.org/doc/Documentation/locking/lockdep-design.txt)
