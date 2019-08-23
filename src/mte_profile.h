/* Performance profiling for event-driven system
 * David A. Butterfield
 *
 * Note:  When measuring, set power management so that CPUs run always at 100%
 */
#ifndef MTE_PROFILE_H
#define MTE_PROFILE_H
#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <search.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <sys/syscall.h>
#define gettid()                        ((pid_t)(syscall(SYS_gettid)))	/* thread-id */
#define tkill(tid, sig)			(syscall(__NR_tkill, tid, sig)) /* thread signal */

#define __STRINGIFY(TOKEN)		#TOKEN
#define __stringify(TOKEN)		__STRINGIFY(TOKEN)
#define _FL_STR				__FILE__":"__stringify(__LINE__)
#define _FN_STR				__func__

#define PREDICT(e, p)			__builtin_expect((long)(e), (long)(p))
#define likely(e)			PREDICT((e) != 0, true)
#define unlikely(e)			PREDICT((e) != 0, false)

#define PER_THREAD			__thread

struct task * _task_current;		//XXX
#define task_current()			_task_current

typedef uint64_t	htime_t;	/* high-resolution time */
typedef char const    * sstring_t;	/* static string (not to be freed) */
typedef char const    * string_t;	/* dynamic string (to be freed) */

typedef struct task   * task_t;
typedef void	      * env_t;

/* A closure handler takes a void * environment and returns void */
typedef void (*handler_t)(env_t env);

/* A closure specifies a task context, a handler entry point, and the handler's environment */
typedef struct {
    task_t		task;
    handler_t		handler;
    env_t		env;
} closure_t;

/* Return high-resolution time */
static inline htime_t
htime_now(void)
{
    uint32_t a, d;
    __asm__ volatile("rdtsc" : "=a" (a), "=d" (d));
    return ((uint64_t)a) | (((uint64_t)d) << 32);
}

htime_t htime_mhz = 2400;   //XXX

static inline uint64_t
htime_to_nsec(htime_t htime_delta)
{
    return htime_delta * 1000 / htime_mhz;
}

/* Here, "dispatch" refers to an explicit, synchronous invocation of a separable segment of
 * thread execution, called from the event loop or from another segment of thread execution.
 *
 * The lifecycle of a dispatch proceeds through four milestones delineating three phases:
 *	    creation of the dispatch request	-- e.g. requestor sets a timer alarm
 *    [trigger delay phase]
 *	    triggering of the dispatch		-- e.g. timer alarm expires
 *    [scheduling latency phase]
 *	    Starting of the dispatch		-- synchronous call to event handler function
 *    [execution phase]
 *	    Finishing the dispatch		-- synchronous return from event handler
 */

/* Dispatch node types, denoting types of activity the node represents */
/*	Type		request      trigger     start       finish	    detected by	      */
typedef enum {
	/* asynchronous trigger-to-start */
    DISP_SCHED,	    /*  requested   scheduled   call        return	    general workqueue */
    DISP_ALARM,	    /*  requested   expires     call        return	    timer expiration  */
    DISP_FDESC,	    /*  requested   fd_ready    call        return	    file desc ready   */
	/* synchronous trigger-to-start */
    DISP_APPLY,	    /*  requested	        call        return	    closure apply     */
    DISP_CALL,	    /*  		        call        return	    explicit in code  */
    DISP_SOCKIOR,   /*  		        call	    return	    sockio read call  */
    DISP_SOCKIOW,   /*  		        call	    return	    sockio write call */
    DISP_BLOCK,	    /*  		        blocked     unblocked	    epoll_wait call   */
    DISP_EVENT,	    /*					    reached	    explicit in code  */
    DISP_MUTEX,	    /*  	    first_try	acquired    released	    mutex spin/hold   */
} calltype_t;

/* A "dispatch node" represents the execution of a handler function called at the start of a
 * segment of thread execution, as invoked synchronously by a specific calling dispatch node.
 *
 * Each node points to the node of its caller; this forms for each thread a shallow synchronous-
 * call tree rooted at the event loop (whence all activity in the thread is driven).  If a
 * handler is directly called by multiple dispatch nodes, it will appear in a separate dispatch
 * node instance of its own for each of the callers.
 *
 * The synchronous-invocation tree is represented on visual graphs by colored arrows pointing
 * from calling nodes to called (target) nodes.  The color of an arrow can be used when perusing
 * the graph to readily distinguish activity chains triggered by socket events, timer
 * expirations, or work taken from the thread's general scheduler work queue.  Each node has
 * exactly one incoming colored arrow, from its direct caller.
 */
typedef struct disp_node_s * disp_node_t;
typedef struct disp_node_s {
    disp_node_t		caller;		/* direct synchronous caller of the target */
    void	      * handler;	/* address of target handler */
    task_t		task;		/* task of caller and target (implies thread) */
    calltype_t		type;		/* type of activity represented by the target node */
	/* above are hashtable key fields */
} * disp_node_t;

/* A "dispatch request" represents a target dispatch node whose handler is to be invoked, as
 * requested by a specific requesting dispatch node executing at a particular location in the
 * code.  If some disp_node  R  requests multiple dispatches of the same target disp_node  T
 * from different locations in the source code running R, then execution statistics for
 * dispatches of T requested from each such locations in R are maintained as distinct in
 * separate disp_req records.
 *
 * Each disp_req record pairs a requesting node with a target node, represented on graphs as a
 * grey arrow from the requesting node to the target node.  A single target node may have
 * multiple requestors, and all of their (grey) arrows point to the target node.  Unlike the
 * colored "call subgraph", the grey "request subgraph" is not a tree and may contain cycles.
 *
 * Statistics regarding the timing of dispatch lifecycle phases are accumulated here; so
 * separate target dispatch node execution statistics are maintained with per-target
 * per-requestor-and-request-point granularity.
 */
typedef struct {
    disp_node_t		target;		/* target disp_node of the closure */
    disp_node_t		requestor;	/* requestor disp_node */
    sstring_t		req_fl;		/* __FILE__:__LINE__ of requestor */
    sstring_t		targ_fl;	/* __FILE__:__LINE__ of target */
	/* above are hashtable key fields */
    uint64_t		n_dispatch;	/* number of dispinfo entries summed */
    htime_t		t_accum_r_t;	/* sum(t_trigger - t_request)  trigger delay */
    htime_t		t_accum_t_s;	/* sum(t_start   - t_trigger) scheduling latency */
    htime_t		t_accum_s_f;	/* sum(t_finish  - t_start)   execution time */
	/* could add other stats per disp_req here; e.g. socket I/O volume, etc */
} * disp_req_t;

/* At any given time, each thread has a "current" dispatch request call in progress.  The event
 * loop runs in a "root" dispatch call.  When a callout is made from the event loop to process
 * thread activites, the thread's "current" dispatch call is saved and then changed to denote
 * the (nested) activity being started.  During the execution of the dispatch, statistics are
 * accumulated into the "current" dispatch call record.  After the dispatch handler returns, the
 * "current" dispatch call pointer is restored back to refer to the previously-saved instance.
 */
extern PER_THREAD disp_req_t _dispatch_current;    /* use accessors below */

static inline disp_req_t
disp_current(void)
{
    assert(_dispatch_current);
    return _dispatch_current;
}

static inline void
disp_current_set(disp_req_t disp_req)
{
    assert(disp_req);
    _dispatch_current = disp_req;
}

/* XXX hashtables */

/* Locate and return the dispatch's entry in the hashtable, adding it if necessary */
static inline disp_req_t
disp_req_lookup_add(disp_req_t caller, handler_t handler, task_t task, calltype_t type, 
		    disp_req_t requestor, sstring_t req_fl, sstring_t trig_fl)
{
    //XXX
}

/* PER_THREAD static disp_node hashtable */
/* PER_THREAD static disp_req hashtable */
/* PER_THREAD static stats epoch */

/* A "disp_info" structure holds information about a dispatch request that has been created but
 * not finished.  When the dispatch finishes, the recorded disp_info is used to update the
 * accumulated statistics for the associated disp_req record, and the disp_info is discarded.
 *
 * Note that we cannot even determine the correct disp_req record any sooner than dispatch start
 * time, because the synchronously-calling disp_node is part of the disp_node hashtable key, and
 * we don't learn the identity of the caller until it makes the call.  We could compute the
 * correct entry at dispatch start time, but with this structure we don't actually need it until
 * dispatch end time.
 *
 * At dispatch start and end time we know the calling node (which we save over the duration of
 * the dispatch).  We also can determine the type of dispatch running and what task it is
 * running on.  That information plus the "handler" field in the disp_info provides the required
 * key information to lookup in the hashtable the correct disp_node for the target.
 *
 * Knowledge of target, plus the disp_info key fields, provide the key to lookup the matching
 * disp_req structure.
 */
typedef struct {
    disp_req_t		requestor;	/* creator of the request */
    sstring_t		req_fl;		/* request __FILE__:__LINE__ */
    htime_t		t_request;	/* create time */

    disp_req_t		trig_disp;	/* triggering dispatch */
    sstring_t		trig_fl;	/* trigger __FILE__:__LINE__ */
    htime_t		t_trigger;	/* trigger time */

    void	      * handler;	/* address of target handler */
    htime_t		t_start;	/* call time */

    disp_req_t		pushed_disp;	/* saved previous disp_current() */
} disp_info_t;

/* Accumulate stats for the ending dispatch and revert to the dispatch we saved in disp_start */
#define disp_finish(info) disp_finish_ffl(info, htime_now())
static inline void
disp_finish_ffl(disp_info_t info, htime_t t_finish)
{
    disp_req_t disp = disp_current();

    /* Accumulate the disp_info phase durations into the disp_req sums */
    disp->n_dispatch++;
    disp->t_accum_r_t += info.t_trigger - info.t_request;
    disp->t_accum_t_s += info.t_start - info.t_trigger;
    disp->t_accum_s_f += t_finish - info.t_start;

    disp_current_set(info.pushed_disp);	/* restore disp_current() to what we saved earlier */
}

/* Use info and "current" dispatch to compute a new "current" dispatch and switch to it */
#define disp_start(info) disp_start_ffl(info, htime_now())
static inline disp_info_t
disp_start_ffl(disp_info_t info, htime_t t_start)
{
    assert(info.t_start == 0);
    disp_req_t caller_req = disp_current();
    assert(caller_req->target->task == task_current());

    /* Locate the dispatch's entry in the hashtable, adding if necessary */
    disp_req_t newdisp = disp_req_lookup_add(caller_req, info.handler,
					      caller_req->target->task,
					      caller_req->target->type,
					      info.requestor, info.req_fl, info.trig_fl);

    /* set disp_current() for dispatch we're switching to */
    disp_current_set(newdisp);

    info.pushed_disp = caller_req;  /* save the old dispatch context */
    info.t_start = t_start;	    /* record dispatch start time */
    return info;
}

/* Declare a dispatch to be ready for execution and its invocation triggered */
#define disp_trigger(info) disp_trigger_ffl(info, htime_now(), _FN_STR, _FL_STR)
static inline disp_info_t
disp_trigger_ffl(disp_info_t info, htime_t t_trigger, sstring_t trig_func, sstring_t trig_fl)
{
    assert(info.t_trigger == 0);
    assert(info.t_start == 0);
    info.t_trigger = t_trigger;	    /* record dispatch trigger time */
    info.trig_fl = trig_fl;	    /* record source file and line of triggering caller */
    return info;
}

/* Return a fresh a disp_info record for possible future triggering and invocation */
#define disp_create(handler) disp_create_ffl(handler, htime_now(), _FN_STR, _FL_STR)
static inline disp_info_t
disp_create_ffl(handler_t handler, htime_t t_request, sstring_t req_func, sstring_t req_fl)
{
    disp_info_t info;
    info.requestor = disp_current();
    info.req_fl = req_fl;
    info.trig_fl = NULL;
    info.handler = handler;
    info.t_request = t_request;
    info.t_trigger = 0;
    info.t_start = 0;
    info.pushed_disp = NULL;
    return info;
}


    DISP_BLOCK,	    /*  		        blocked     unblocked	    epoll_wait call   */
    DISP_EVENT,	    /*					    reached	    explicit in code  */
    DISP_MUTEX,	    /*  	    first_try	acquired    released	    mutex spin/hold   */


#define disp_schedule(disp)		disp_trigger(disp)
#define disp_timer_expire(disp, when)	disp_trigger_ffl(disp, when, _FN_STR, _FL_STR)
#define disp_fd_ready(disp)		disp_trigger(disp)
#define disp_return(disp)		disp_finish(disp)
#define disp_apply(disp)		disp_start(disp_trigger(disp))

#define disp_call(handler)		disp_start(disp_trigger(disp_create(DISP_CALL, handler)))
#define disp_sockior(handler)		disp_start(disp_trigger(disp_create(DISP_SOCKIOR, handler)))
#define disp_sockiow(handler)		disp_start(disp_trigger(disp_create(DISP_SOCKIOW, handler)))
#define disp_block(disp)		disp_start(disp_trigger(disp_create(DISP_BLOCK, handler)))

#define disp_event(disp)		disp_finish(disp_start(disp_trigger(disp_create(DISP_EVENT, handler))))

#define disp_mutex_try(disp)		disp_trigger(disp_create(DISP_MUTEX, NULL))))
#define disp_mutex_acquire(disp)	disp_start(disp)
#define disp_mutex_release(disp)	disp_finish(disp)

#endif /* MTE_PROFILE_H */
