/* mte_event_task.c
 * Copyright 2016 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Event thread implementation supports timer alarms, file descriptor polling,
 * and two general work queues, one with reduced priority.
 */
#define NAME MTE_EVENT
#include <signal.h>
#include <sys/signalfd.h>

#include <sys/eventfd.h>
#include <sys/epoll.h>

#include "mte_util.h"
#include "mte_mttypes.h"
#include "mte_mem.h"

#define MTE_EVENT_DEBUG 1
#if MTE_EVENT_DEBUG
/* Observability of active polls under gdb */
struct sys_poll_entry * polls_active_read[4096];
struct sys_poll_entry * polls_active_write[4096];
#endif

static mem_cache_t MTE_sched_cache;
static mem_cache_t MTE_alarm_cache;
static mem_cache_t MTE_poll_cache;

/* There is one struct event_task for each event thread */
typedef struct sys_event_task {
    sys_thread_t	    SYS;	    /* pointer to system thread info */

    uint64_t       volatile odometer;	    /* number of work callbacks completed */
    bool           volatile is_stopping;    /* flag to exit event_loop */

    /* file descriptor polling */
    int			    epfd;	    /* epoll(2) file descriptor */
    uint32_t		    max_polls;	    /* max poll events per check */
    int32mt_t		    npolls;	    /* number of active file-descriptor polls */

    /* queued work backlog */
    uint32_t		    max_steps;	    /* max backlog callbacks before poll check */
    sys_fifo_t		    sched;	    /* used single-consumer */
    sys_fifo_t		    sched_lopri;    /* used single-consumer */

    /* unexpired timer callbacks */
    sys_fifo_t		    alarm;	    /* used single-consumer */

    bool           volatile is_engaged;	    /* a sys_thread is active in the event_task */
    sys_time_t	   volatile heartbeat;	    /* time of last alarm check */
    sys_time_t	   volatile alarm_time_next;/* time of next alarm check */

    pid_t		    tid;	    /* thread ID checks */
    sys_time_t		    dob;	    /* creation time */
    sys_poll_entry_t	    signal_pe;	    /* poll entry for our signal fd */

    /* cross-thread wakeup */
    sys_poll_entry_t	    wakeup_pe;	    /* poll entry for our wakeup fd */
    int32mt_t		    is_awake;	    /* needs a wakeup if zero */
} * sys_event_task_t;

#define event_task_epfd(event_task)	((event_task)->epfd)

sstring_t
sys_event_task_name(sys_event_task_t event_task)
{
    return event_task->SYS ? sys_thread_name(event_task->SYS) : "<not yet started>";
}

uint32_t
sys_event_task_num(sys_event_task_t event_task)
{
    return event_task->SYS ? sys_thread_num(event_task->SYS) : 0;
}

/* If event_task is not the current event_task, wait for the event_task to return from its
 * current scheduler dispatch (or be idle/disengaged)
 */
static inline void
mte_event_task_sync(sys_event_task_t event_task, sstring_t why)
{
    if (event_task == this_event_task()) return;

    lcount_t nspins = 0;
    uint64_t task_milage = event_task->odometer;
    while (event_task->is_engaged && int32mt_get(&event_task->is_awake)
			      && event_task->odometer == task_milage) {
	++nspins;
	SYS_SPINWAITING();
    }

    if (nspins > 10)
	trace("%s: nspins=%"PRIu64" odometer=%"PRIu64" %s %s",
		why, nspins, task_milage,
		event_task->is_engaged ? "ENGAGED" : "DISENGAGED",
		int32mt_get(&event_task->is_awake) ? "AWAKE" : "IDLE");
    else
	trace_verbose("%s: nspins=%"PRIu64" odometer=%"PRIu64" %s %s",
		why, nspins, task_milage,
		event_task->is_engaged ? "ENGAGED" : "DISENGAGED",
		int32mt_get(&event_task->is_awake) ? "AWAKE" : "IDLE");
}

/******************************************************************************/

/* A callback function receives a first argument specified by the callback creator,
 * along with second and third arguments provided by the callback invoker, as:
 *	  void fn(void * creator_env, uintptr_t invoker_arg, errno_t invoker_err);
 */
typedef struct {
    void		  (*fn)(void * env, uintptr_t arg, errno_t);
    void		  * env;	/* first argument to fn */
    sys_event_task_t	    owner;	/* event_task to execute the callback */
} callback_t;

#define callback_init(_owner, _fn, _env) ((callback_t){ \
					    .owner = (_owner), \
					    .fn = (_fn), \
					    .env = (_env), })

/* Invoke a callback by direct synchronous function call */
static inline void
callback_deliver(callback_t * cb, uintptr_t arg, errno_t err)
{
    assert_this_event_task_is(cb->owner);   /* Delivering to the correct thread */

    cb->fn(cb->env, arg, err);

    ++this_event_task()->odometer;
}

/******************************************************************************/

/* Event file-descriptors (in non-semaphore mode) facilitate waking an event thread */

/* Create and return a new EVENT file descriptor --
 * NON-semaphore mode delivers available events to the consumer all at one time;
 * Semaphore mode delivers events to the consumer one at a time
 */
static inline int
_eventfd_create(sstring_t const name, uint32_t const flags)
{
    int fd;
    RETRY_EINTR(fd, eventfd(0, flags));
    verify_rc(fd, eventfd);
    trace("new event fd name='%s' fd=%d", name, fd);
    return fd;
}

/* Create and return a new EVENT file descriptor in NON-semaphore mode */
/* NON-semaphore mode delivers available events to the consumer all at one time */
int
sys_eventfd_create(sstring_t const name)
{
    return _eventfd_create(name, EFD_NONBLOCK | EFD_CLOEXEC);
}

/* Create and return a new EVENT file descriptor in semaphore mode */
/* Semaphore mode delivers events to the consumer one at a time */
int
sys_eventfd_create_sem(sstring_t const name)
{
    return _eventfd_create(name, EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE);
}

void
sys_eventfd_close(int const fd)
{
    int rc = sock_op(fd, close);
    assert_eq(rc, 0, "close");
}

/* Add count to the eventfd */
void
sys_eventfd_write(int const fd, uint64_t const count)
{
    int const rc = eventfd_op(fd, eventfd_write, count);
    if (rc == 0) return;
    sys_error("eventfd %u write count=%"PRIu64, fd, count);
    assert_eq(rc, -1);
}

/* Returns the count read from (eventfd), or -1 for fatal error on the eventfd --
 * in semaphore mode the count is always either zero (empty) or one (non-empty);
 * in NON-semaphore mode returns and clears the entire count.
 */
uint64_t
sys_eventfd_read(int const eventfd)
{
    uint64_t ret = 0;
    int const rc = eventfd_op(eventfd, eventfd_read, &ret);
    if (rc == 0) {
	return (int64_t)ret;	    /* EAGAIN returns zero here */
    }
    sys_error("eventfd %u read", eventfd);
    assert_eq(rc, -1);
    return (-1);
}

/******************************************************************************/
/* File-descriptor event polling -- NOTE:  The model used here can be EDGE triggered --
 * in which case consumers must exhaust the cause of the event before another event can
 * be guaranteed; on the other hand, you don't have to keep switching XMIT polling on&off
 */

/* There is one struct poll_entry for each fd being polled by an event thread */
typedef struct sys_poll_entry {
    callback_t		    cb;		    /* callback to notify upon event */
    int			    fd;
    bool		    disabled;
    sstring_t		    name;
} * sys_poll_entry_t;

/* Poll (epfd) for ready file descriptors --
 * up to (max_events) ready events are returned through (events) array;
 * event_poll returns the number of events written into the array;
 * timeout_ms (0): no wait; (-1): arbitrary wait; else milliseconds maximum wait
 */
static inline uint32_t
event_poll(int const epfd, struct epoll_event * const events, uint32_t const max_events,
							      int const timeout_ms)
{
    assert(events);
    assert_ae(max_events, 1);
    assert_ae(timeout_ms, 0);
    int err = 0;

    /* We don't want the RETRY_EINTR() here */
    int rc = epoll_wait(epfd, events, max_events, timeout_ms);
    if (rc < 0) {
	/* EINTR acceptable, any other errors imply a program bug */
	err = errno;
	assert_eq(rc, -1);
	if (err != EINTR) {
	    sys_panic_err(err, "epoll_pwait");
	}
	rc = 0;	    /* EINTR happened, ignore it and report zero events */
    }

    return (uint32_t)rc;    /* return the number of events now in the array */
}

/* Deliver ready file descriptor events to their respective callbacks */
static inline void
event_poll_deliver(struct epoll_event const * const events, uint32_t const nevents)
{
    unsigned int idx;
    for (idx = 0; idx < nevents; idx++) {
	sys_poll_entry_t pe = (void *)events[idx].data.u64;
	uint32_t const ev = events[idx].events;
	if (likely(!pe->disabled)) {
	    trace_verbose("event_poll_deliver event notification '%s'", pe->name);
	    callback_deliver(&pe->cb, ev, E_OK);    /* deliver fd events to callback */
	} else {
	    /* Race with EPOLL_CTL_DEL */
	    trace("intercepted event_poll callback to disabled '%s'", pe->name);
	}
    }
}

/* Call from any thread to enable polling of (fd) for (events) on (thread) --
 * a callback to
 *			fn(env, ready_events, errno_t)
 *
 * will be made whenever one or more of the specified (events) might have become ready, with
 * the result of the epoll passed via (ready_events) and (errno_t)
 */
sys_poll_entry_t
mte_poll_enable(sys_event_task_t event_task, void (*fn)(void *, uintptr_t, errno_t),
		void * env, int fd, unsigned long events, string_t name)
{
    assert(events);
    sys_poll_entry_t pe = mem_cache_alloc(MTE_poll_cache);
    pe->fd = fd;
    pe->cb = callback_init(event_task, fn, env);
    pe->name = name;

    int const epfd = event_task_epfd(event_task); /* prepare to update thread's epoll list */

    struct epoll_event event;
    record_zero(&event);
    event.data.u64 = (uintptr_t)pe;	    /* our callback function argument */
    event.events = events;

    int rc = epoll_ctl(epfd, EPOLL_CTL_ADD, pe->fd, &event);

    /* The MOD case is not expected to be frequent in edge-triggered mode,
     * or for aio eventfd's -- it has not been optimized
     */
    if (rc != 0 && errno == EEXIST) {
	rc = epoll_ctl(epfd, EPOLL_CTL_MOD, pe->fd, &event);
    }

    verify_rc(rc, epoll_ctl, "EPOLL_CTL_ADD epfd=%u op=%u fd=%u event=0x%"PRIx64,
			     epfd, EPOLL_CTL_ADD, pe->fd, events);

    int32mt_inc(&event_task->npolls);

#if MTE_EVENT_DEBUG
    if (events & EPOLLIN) {
	if (polls_active_read[pe->fd]) {
	    sys_warning("Thread %d enables polling by event thread %d of fd=%d already polled by thread %d",
			    gettid(), event_task->tid, pe->fd, pe->cb.owner->tid);
	}
	polls_active_read[pe->fd] = pe;
    }

    if (events & EPOLLOUT) {
	if (polls_active_write[pe->fd]) {
	    sys_warning("Thread %d enables polling by event thread %d of fd=%d already polled by thread %d",
			    gettid(), event_task->tid, pe->fd, pe->cb.owner->tid);
	}
	polls_active_write[pe->fd] = pe;
    }
#endif

    trace_verbose("ENABLE events=0x%"PRIx64" on '%s' fd=%d on event_task '%s' [%u] ",
		  events, pe->name, fd,
		  sys_event_task_name(event_task), sys_event_task_num(event_task));

    /* We have added the new poll directly to the thread's epfd poll-list, and that is
     * supposed to enable the new event for the thread without any need to wake it up
     */
    return pe;
}

/* On-thread free of a poll_entry previously disabled -- this is done on-thread so
 * that it stays valid long enough to outlive any callback deliveries referencing it.
 */
static void
mte_poll_entry_free(void * v_pe, uintptr_t arg, errno_t err)
{
    assert_eq(err, E_OK);
    sys_poll_entry_t pe = v_pe;
    assert(pe->disabled);
    mem_drop(pe);
}

/* Call from any thread to disable polling of (pe) on event_task */
static void
_mte_poll_disable_sync(sys_event_task_t event_task, sys_poll_entry_t pe)
{	
    pe->disabled = true;

    int const epfd = event_task_epfd(event_task);
    int const rc = epoll_ctl(epfd, EPOLL_CTL_DEL, pe->fd, NULL);
    expect_rc(rc, epoll_ctl, "EPOLL_CTL_DEL epfd=%u op=%u fd=%u", epfd, EPOLL_CTL_DEL, pe->fd);

    trace_verbose("DISABLE '%s' fd=%d on event_task '%s' [%u] ",
		  pe->name, pe->fd,
		  sys_event_task_name(event_task), sys_event_task_num(event_task));

    mte_event_task_sync(event_task, __func__);		/* ensure out of callback */

#if MTE_EVENT_DEBUG
    if (pe == polls_active_read[pe->fd])
	polls_active_read[pe->fd] = NULL;
    if (pe == polls_active_write[pe->fd])
	polls_active_write[pe->fd] = NULL;
#endif

    int32mt_dec(&event_task->npolls);
}

/* Call from any thread to disable polling of (pe) on event_task and free pe */
void
mte_poll_disable_sync(sys_event_task_t event_task, sys_poll_entry_t pe)
{	
    _mte_poll_disable_sync(event_task, pe);
    mte_callback_schedule(event_task, mte_poll_entry_free, pe, 0, E_OK, "free sys_poll_entry");
}

/******************************************************************************/

/* Cross-thread wakeup handler invoked after someone wrote our wakeup file descriptor */
static void
wakeup_handler(void * const env, uintptr_t const u_events, errno_t err)
{
    sys_event_task_t const event_task = env;
    assert_this_event_task_is(event_task);
    unsigned long events = u_events;
    assert(events & EPOLLIN);
    assert_eq(err, E_OK);

    int const rc = sys_eventfd_read(event_task->wakeup_pe->fd);
    verify_rc(rc, sys_eventfd_read);

    /* We don't need to do any actual work here -- the event_loop is now active and whatever
     * work was scheduled from another thread will be processed by the loop as normal.
     */
    trace_verbose("event_task %u awake, received %d wakeup",
		  sys_thread_num(sys_thread_current()), rc);
}

/* Wake up an event thread -- to get it to to do some particular work, put the work
 * on one of the thread's scheduler queues before calling here
 */
static inline void
wakeup(sys_event_task_t const event_task)
{
    if (likely(int32mt_inc(&event_task->is_awake) > 1)) {
	return;		/* target event_task was already awake or awakening */
    }

    if (unlikely(event_task == this_event_task())) {
	/* Trying to wake myself, and if I'm here I'm already awake (transition-to-idle
	 * has a window during which we can arrive at this function with is_awake zero) */
	return;
    }

    /* Make the target event_task's wakeup fd go ready */
    trace_verbose("thread '%s' (%u) waking up event_task '%s' (%u)",
		  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
		  sys_event_task_name(event_task), sys_event_task_num(event_task));
    sys_eventfd_write(event_task->wakeup_pe->fd, 1);
}

/******************************************************************************/

/* An alarm entry issues a callback at or after expire time */
typedef struct sys_alarm_entry {
    sys_link_t		    link;
    callback_t		    cb;
    sys_time_t	   volatile expire;
    sstring_t		    name;
} * sys_alarm_entry_t;

/* Process all expired alarms, returning true if at least one was processed */
static inline bool
alarm_process(sys_event_task_t const event_task, sys_time_t const now)
{
    assert_this_event_task_is(event_task);
    sys_fifo_t * const fifo = &event_task->alarm;
    bool did_work = false;

    do {
	sys_spin_lock(&fifo->lock);	//XXX fifo guts don't belong in here...

	if (sys_fifo_is_empty(fifo)) break;
	if (unlikely(fifo->nitem == 0)) break;
	sys_alarm_entry_t ae = enclosing_record(fifo->head.next, sys_alarm_entry_t, link);
	if (ae->expire > now) break;

	fifo->head.next = ae->link.next;
	--fifo->nitem;

	sys_spin_unlock(&fifo->lock);

	callback_deliver(&ae->cb, now, E_OK);
	mem_drop(ae);
	did_work = true;
    } while (true);
    sys_spin_unlock(&fifo->lock);

    return did_work;
}

/* Return -1, 0, or 1 -- depending on whether x < y, x == y, or x > y */
static int
alarm_entry_cmp(void * unused, sys_link_t * x, sys_link_t * y)
{
    assert_eq(unused, NULL);
    sys_alarm_entry_t alarm_x = enclosing_record(x, sys_alarm_entry_t, link);
    sys_alarm_entry_t alarm_y = enclosing_record(y, sys_alarm_entry_t, link);
    if (alarm_x->expire < alarm_y->expire) return -1;
    if (alarm_x->expire > alarm_y->expire) return 1;
    return 0;
}

/* Call from any thread to create a new alarm callback and set it to occur on (event_task)
 * at (expire) time, as
 *			fn(env, sys_time_t now, errno_t)
 *
 * with the time of the alarm delivery passed to (fn) via (now)
 */
sys_alarm_entry_t
mte_alarm_set(sys_event_task_t event_task,
	  void (*fn)(void *, uintptr_t, errno_t), void * env,
	  sys_time_t const expire, sstring_t name)
{
    sys_alarm_entry_t const ae = mem_cache_alloc(MTE_alarm_cache);
    ae->expire = expire;
    ae->cb = callback_init(event_task, fn, env);
    ae->name = name;

    sys_fifo_insert_sorted(&event_task->alarm, &ae->link, alarm_entry_cmp, NULL);

    if (expire < event_task->alarm_time_next) {
	wakeup(event_task);	/* jab event_task to reset its timer sooner */
    }

    return ae;
}

/* Call from any thread to cancel an unexpired alarm --
 * returns EINVAL if the alarm was not found on the event_task's list.
 * Cancellations are not expected to be frequent and are not optimized
 */
errno_t
mte_alarm_cancel_sync(sys_event_task_t event_task, sys_alarm_entry_t const alarm)
{
    errno_t err = sys_fifo_find_remove(&event_task->alarm, &alarm->link);
    trace_verbose("find_remove(&event_task->alarm, &alarm[%s]@%p->link) returns %d", alarm->name, alarm, err);
    if (err == E_OK) {
	/* Found and removed the entry; its callback was not executed */
	mem_drop(alarm);
    } else {
	/* In case of the race where the event_task was still executing the callback
	 * we couldn't find, wait for the event_task to return from its current
	 * scheduler dispatch (which is supposed to be short).  At that point
	 * any possible callback is over (and the alarm handler has responsibility
	 * to free that alarm_entry which it took from the queue).
	 */
	mte_event_task_sync(event_task, __func__);	/* ensure out of callback */
    }
    return err;
}

/******************************************************************************/

/* Sched entries are general work items (callbacks) to be executed by an event_task
 * taking them one at a time from the head of a scheduler queue and issuing the callbacks
 * sequentially in the order they were enqueued.  Entries are executed "as soon as
 * possible" subject to the ordering and single-threaded constraints.
 *
 * Entries on one sched queue are not ordered with respect to entries on a different queue,
 * only with respect to other entries on the same sched queue.  Each event thread has two
 * queues: sched and sched_lopri, with items being taken for execution from sched_lopri
 * only when the main sched queue is empty.
 */
typedef struct sys_sched_entry {
    sys_link_t		link;
    callback_t		cb;		/* callback function and first argument */
    uintptr_t		arg;		/* second argument to cb.fn */
    errno_t		err;		/* third argument to cb.fn */
    bool		free_me;        /* unset for embedded sched_entries */
    char        const * name;           /* debugging string for this entry */
} * sys_sched_entry_t;

/* Return the next sched entry to process, or NULL if queues are empty */
static inline sys_sched_entry_t
sched_next(sys_event_task_t const event_task)
{
    sys_sched_entry_t e;

    e = sys_fifo_take_entry(&event_task->sched, sys_sched_entry_t, link);
    if (e) {
	return e;	    /* found something to do */
    }

    e = sys_fifo_take_entry(&event_task->sched_lopri, sys_sched_entry_t, link);
    if (e) {
	return e;	    /* found something to do */
    }

    return NULL;	    /* no sched entries pending to do */
}

/* Process some sched entries -- return true if there is (possibly) still more work to do */
/* Sched entries for an event_task are processed one at a time in the order received */
static inline bool
sched_process(sys_event_task_t const event_task)
{
    assert_this_event_task_is(event_task);
    uint32_t step_count_remaining = event_task->max_steps;

    while (step_count_remaining--) {
	sys_sched_entry_t const e = sched_next(event_task);
	if (!e) return false;	    /* no more work on sched queues */
	bool const free_me = e->free_me;

	callback_deliver(&e->cb, e->arg, e->err);
	/* Note that e may no longer exist now (in which case !free_me) */

	if (free_me) mem_drop(e);
    }
    return true;	    /* possibly (probably) more work to do */
}

/* Primitives for creating and enqueueing sched entries */

/* Sched entries embedded in other objects should not set free_me */
static inline sys_sched_entry_t
sched_entry_alloc(void)
{   
    sys_sched_entry_t e = mem_cache_alloc(MTE_sched_cache);
    e->free_me = true;	/* independent dynamic sched_entry allocation */
    return e;
}

/* Initialize a sched_entry */
static inline void
sched_entry_prep(sys_sched_entry_t e, sys_event_task_t event_task,
		 void (*fn)(void *, uintptr_t, errno_t),
		 void * env, uintptr_t arg, errno_t err, sstring_t name)
{
    e->cb = callback_init(event_task, fn, env);
    e->arg = arg;
    e->err = err;
    e->name = name;	/* static (non-freeable) debugging ID string */
}

static inline void
sched_entry_add(sys_event_task_t event_task, sys_fifo_t * sched_queue, sys_sched_entry_t e)
{
    sys_fifo_append(sched_queue, &e->link);
	    /*** note that e may already no longer exist ***/
    wakeup(event_task);	/* jab event_task to check its sched queues */
}

/* All-in-one functions to allocate and enqueue a new sched entry */

sys_sched_entry_t
mte_callback_schedule(sys_event_task_t event_task,
	       void (*fn)(void *, uintptr_t, errno_t), void * env, uintptr_t arg, errno_t err,
	       sstring_t name)
{
    assert(fn);
    sys_sched_entry_t const e = sched_entry_alloc();
    sched_entry_prep(e, event_task, fn, env, arg, err, name);
    sched_entry_add(event_task, &event_task->sched, e);
	    /*** note that e may already no longer exist ***/
    return e;
}

sys_sched_entry_t
mte_callback_schedule_lopri(sys_event_task_t event_task,
	       void (*fn)(void *, uintptr_t, errno_t), void * env, uintptr_t arg, errno_t err,
	       sstring_t name)
{
    assert(fn);
    sys_sched_entry_t const e = sched_entry_alloc();
    sched_entry_prep(e, event_task, fn, env, arg, err, name);
    sched_entry_add(event_task, &event_task->sched_lopri, e);
	    /*** note that e may already no longer exist ***/
    return e;
}

/* Cancellations are not expected to be frequent and are not optimized */
static inline errno_t
_mte_callback_cancel_sync(sys_event_task_t event_task, sys_fifo_t * schedq, sys_sched_entry_t e)
{
    errno_t err = sys_fifo_find_remove(schedq, &e->link);
    if (err == E_OK) {
	/* Found and removed the entry; its callback was not executed */
	mem_drop(e);
    } else {
	mte_event_task_sync(event_task, __func__);	/* ensure out of callback */
    }
    return err;
}

errno_t
mte_callback_cancel_sync(sys_event_task_t event_task, sys_sched_entry_t e)
{
    return _mte_callback_cancel_sync(event_task, &event_task->sched, e);
}

errno_t
mte_callback_cancel_lopri_sync(sys_event_task_t event_task, sys_sched_entry_t e)
{
    return _mte_callback_cancel_sync(event_task, &event_task->sched_lopri, e);
}

/******************************************************************************/

static errno_t
event_task_loop(sys_event_task_t const event_task)
{
    while (likely(!event_task->is_stopping)) {
	uint64_t task_milage = event_task->odometer;

	/* Issue epoll call to read ready events, but do not delay awaiting such events */
	struct epoll_event event[event_task->max_polls];
	uint32_t nfd_ready = event_poll(event_task->epfd, event, event_task->max_polls, 0);
	assert_be(nfd_ready, event_task->max_polls);

	/* Deliver the events returned by the epoll (sockets, aio, or other file descriptors) */
	if (likely(nfd_ready)) {
	    event_poll_deliver(event, nfd_ready);
	}

	/* Process some enqueued work (if any) */
	sched_process(event_task);

	/* Check for expired alarms and deliver any and all of them */
	sys_time_t now = event_task->heartbeat = NOW();
	alarm_process(event_task, now);

	if (likely(event_task->odometer != task_milage)) {
	    /* We (maybe) didn't exhaust all pending work */
	    int32mt_inc(&event_task->is_awake);
	    continue;
	}

	/* Exhausted all pending work */
	if (int32mt_get(&event_task->is_awake)) {
	    int32mt_clr(&event_task->is_awake); /* let other threads know we'll need a wakeup */
	    continue;				/* check once more after clearing is_awake */
	}

	/* No work to do right now, so block until next alarm time or fd event */

	/* Compute the expire time of the earliest pending alarm entry */
	sys_time_t alarm_time_next = sys_time_invalid(); /* larger than any valid time */
	sys_fifo_t * fifo = &event_task->alarm;

	sys_spin_lock(&fifo->lock);	//XXX fifo guts don't belong in here...
	{
	    if (likely(fifo->nitem > 0)) {
		alarm_time_next =
		    enclosing_record(fifo->head.next, sys_alarm_entry_t, link)->expire;
	    }
	}
	sys_spin_unlock(&fifo->lock);

	if (alarm_time_next <= now) continue;

	int timeout_ms;
	if (alarm_time_next > now + sys_time_delta_of_sec(1)) {
	    timeout_ms = 1000;	    /* let heartbeat update >= 1 Hz */
	    alarm_time_next = now + sys_time_delta_of_ms(timeout_ms);
	} else {
	    /* Add 1 so that when the event occurs we will find its time expired */
	    timeout_ms = 1 + sys_time_delta_to_ms(alarm_time_next - now);
	}

	event_task->alarm_time_next = alarm_time_next;

	/* Issue epoll call to read ready events, sleeping up to timeout_ms awaiting such */
	nfd_ready = event_poll(event_task->epfd, event, event_task->max_polls, timeout_ms);

		/*** AWAKE ***/
	int32mt_inc(&event_task->is_awake);	    
	event_task->alarm_time_next = 0;

	assert_be(nfd_ready, event_task->max_polls);
	if (likely(nfd_ready)) {
	    /* We got some poll events -- deliver them to their respective callbacks */
	    event_poll_deliver(event, nfd_ready);
	}
    }

    trace("exit event_task event loop\n");
    event_task->is_stopping = false;	/* reset is_stopping flag */
    return E_OK;
}

/******************************************************************************/

void (*sig_handler[32])(uint32_t signum) = { /* empty to start */ };

int mte_signal_handler_set(uint32_t signum, void (*handler)(uint32_t))
{
    if (signum > NELEM(sig_handler)) return EINVAL;
    sig_handler[signum] = handler;
    return E_OK;
}

static void
sigfd_handler(void * const env, uintptr_t const u_events, errno_t e)
{
    sys_event_task_t const event_task = env;
    assert_this_event_task_is(event_task);
    unsigned long events = u_events;
    assert(events & EPOLLIN);
    assert_eq(e, E_OK);
    trace("sigfd_handler");

    struct signalfd_siginfo siginfo;
    ssize_t rc;

    int max_tries = 10;
    while (max_tries-- > 0) {
	RETRY_EINTR(rc, read(event_task->signal_pe->fd, &siginfo, sizeof(siginfo)));
	if (rc > 0) {
	    assert_eq(rc, sizeof(siginfo));
	    break;
	}
	errno_t const err = errno;
	expect_eq(rc, -1);
	expect(err == EAGAIN, "err = %d '%s'", err, strerror(err));
	trace("fd=%d rc=%"PRId64" err=%d '%s'", event_task->signal_pe->fd, rc, err, strerror(err));
	if (err != EAGAIN) return;
    }

    uint32_t signum;

    if (rc <= 0) {
	static int hack = 4;
	if (hack--) return;
	signum = SIGINT;
	sys_warning("sigfd can't seem to read signal -- assume %u", signum);	//XXXX
    } else {
	assert_eq(rc, sizeof(siginfo));
	signum = siginfo.ssi_signo;
	sys_warning("sigfd received signal %u", signum);
    }

    if (signum < NELEM(sig_handler)) {
	void (*handler)(uint32_t) = sig_handler[signum];
	if (handler) {
	    handler(signum);
	}
    }
}

/* Call zero or more times on the event thread -- call event_task_stop to induce
 * event_task_run to return after draining any sched entries already queued.
 * Such event_task_run/event_task_stop pairs may be repeated.
 */
errno_t
mte_event_task_run(sys_event_task_t const event_task)
{
    if (event_task->is_engaged) {
	sys_error("Only one sys_thread should be running an event_task at a time!");
	sys_error("tid=%u is already here ahead of tid=%u", event_task->tid, gettid());
	return EBUSY;
    }

    event_task->is_engaged = true;
    event_task->SYS = sys_thread_current();	/* for logging */
    assert_eq(sys_event_task, NULL);
    sys_event_task = event_task;

    pid_t const prev_tid = event_task->tid;
    event_task->tid = gettid();

    event_task->heartbeat = NOW();

    if (!prev_tid) {
	sys_notice("event_task %s @%p starts up on tid=%u epoll_fd=%d wakeup_fd=%d",
		   sys_thread_name(sys_thread_current()), event_task,
		   sys_thread_num(sys_thread_current()),
		   event_task->epfd, event_task->wakeup_pe->fd);
    } else if (event_task->tid == prev_tid) {
	sys_notice("event_task %s @%p is back again on tid=%u epoll_fd=%d wakeup_fd=%d",
		   sys_thread_name(sys_thread_current()), event_task,
		   sys_thread_num(sys_thread_current()),
		   event_task->epfd, event_task->wakeup_pe->fd);
    } else {
	sys_notice("event_task %s @%p moved from tid=%u to tid=%u epoll_fd=%d wakeup_fd=%d",
		   sys_thread_name(sys_thread_current()), event_task, prev_tid,
		   sys_thread_num(sys_thread_current()),
		   event_task->epfd, event_task->wakeup_pe->fd);
    }

    /* Block these so the event loop can get them through signal_fd */
    errno_t err;
    sigset_t fd_sig;
    sigemptyset(&fd_sig);
    sigaddset(&fd_sig, SIGINT);
//  sigaddset(&fd_sig, SIGQUIT);    //XXX
    err = pthread_sigmask(SIG_BLOCK, &fd_sig, NULL);
    expect_noerr(err, "pthread_sigmask SIG_BLOCK");

    /**************************************/

    errno_t ret = event_task_loop(event_task);	/* Run event loop until stopped */

    /**************************************/

    /* Restore signals */
    err = pthread_sigmask(SIG_UNBLOCK, &fd_sig, NULL);
    expect_noerr(err, "pthread_sigmask SIG_BLOCK");

    sys_notice("event_task %s @%p disengaged -- tid=%u epoll_fd=%d wakeup_fd=%d",
	       sys_thread_name(sys_thread_current()), event_task,
	       sys_thread_num(sys_thread_current()),
	       event_task->epfd, event_task->wakeup_pe->fd);

    event_task->is_engaged = false;
    return ret;
}

/* Process an event_task_stop request on the event_task itself */
static void
event_task_stop_onthread(void * const env, uintptr_t unused, int const rc)
{
    assert_eq(unused, 0);
    assert_eq(rc, E_OK);
    sys_event_task_t const event_task = env;
    assert_this_event_task_is(event_task);
    trace("event_task[%u:%s] stopping", sys_thread_num(sys_thread_current()),
				        sys_thread_name(sys_thread_current()));
    event_task->is_stopping = true;    /* tell myself to exit the event_task_loop */
}

/* Call from any thread to inform the event thread to return from event_task_run
 * after processing any work already queued on its scheduling queues.  Caller may
 * observe the (intercepted) return if it wishes to know when this has happened.
 * mte_event_task_stop should be called once for each prior call to mte_event_task_run.
 */
errno_t
mte_event_task_stop(sys_event_task_t const event_task)
{
    trace_verbose("thread '%s' (%u) schedules stop for event_task '%s' (%u)",
		  sys_thread_name(sys_thread_current()), sys_thread_num(sys_thread_current()),
		  sys_event_task_name(event_task), sys_event_task_num(event_task));

    /* Enqueue the stop at the end of any remaining work items to be drained */
    mte_callback_schedule_lopri(event_task, event_task_stop_onthread, event_task, 0, E_OK,
			    "event_task_stop->onthread");

    return E_OK;
}

static int32mt_t MTE_ntask;	    /* number of event_tasks allocated but not freed */

/* Creating thread may call here before pthread_create, to get an event_task structure */
sys_event_task_t
mte_event_task_alloc(sys_event_task_cfg_t const cfg)
{
    sys_event_task_t const event_task = record_alloc(event_task);
    event_task->max_polls = cfg->max_polls;
    event_task->max_steps = cfg->max_steps;
    int32mt_inc(&event_task->is_awake);	    /* "awake" whenever not in epoll_wait */

    sys_fifo_init(&event_task->sched);
    sys_fifo_init(&event_task->sched_lopri);
    sys_fifo_init(&event_task->alarm);

    /* Create the event polling file descriptor */
    event_task->epfd = epoll_create1(EPOLL_CLOEXEC);
    verify_rc(event_task->epfd, epoll_create1);

    /* Enable cross-thread wakeups for the event_task */
    event_task->wakeup_pe = mte_poll_enable(
				event_task, wakeup_handler, event_task,
				sys_eventfd_create(sys_thread_name(sys_thread_current())),
				EPOLLIN, "cross_thread wakeup");

    sigset_t fd_sig;
    sigemptyset(&fd_sig);
    sigaddset(&fd_sig, SIGINT);
//  sigaddset(&fd_sig, SIGQUIT);    //XXX
    int sig_fd = signalfd(-1, &fd_sig, SFD_NONBLOCK|SFD_CLOEXEC);

    trace("sig_fd=%d", sig_fd);

    event_task->signal_pe = mte_poll_enable(
				event_task, sigfd_handler, event_task,
				sig_fd, EPOLLIN, "signal_fd");

    event_task->dob = NOW();

    int32mt_inc(&MTE_ntask);
    return event_task;
}

/* Called exactly once on any thread, after any and all calls to event_task_run
 * have returned.  Alarms and polls are expected to have already been taken down by
 * the application before making its final call to event_task_stop.
 */
errno_t
mte_event_task_free(sys_event_task_t const event_task)
{
    int fd;
    fd = event_task->wakeup_pe->fd;
    _mte_poll_disable_sync(event_task, event_task->wakeup_pe);
    mem_drop(event_task->wakeup_pe);
    sys_eventfd_close(fd);
    event_task->wakeup_pe = NULL;

    fd = event_task->signal_pe->fd;
    _mte_poll_disable_sync(event_task, event_task->signal_pe);
    mem_drop(event_task->signal_pe);
    close(fd);
    event_task->signal_pe = (void *)MEM_ZAP_64;

    close(event_task->epfd);

    string_t stat_str = NULL;
    trace("mte_event_task[%u:%s] freeing -- stats:\n\t%s",
	  sys_event_task_num(event_task), sys_event_task_name(event_task),
	  stat_str = mte_event_task_fmt(event_task));
    string_free_null(stat_str);


    //XXX improve these diagnostics

    expect_eq(int32mt_get(&event_task->npolls), 0,
	   "event_task being stopped with polls still enabled");

    {	sys_alarm_entry_t e;
	while ((e = sys_fifo_take_entry(&event_task->alarm, sys_alarm_entry_t, link))) {
	    sys_warning("alarm list: '%s'", e->name);
	    mem_drop(e);
	}
	sys_fifo_deinit(&event_task->alarm);
    }

    {	sys_sched_entry_t e;
	while ((e = sys_fifo_take_entry(&event_task->sched, sys_sched_entry_t, link))) {
	    sys_warning("sched list: '%s'", e->name);
	    mem_drop(e);
	}
	while ((e = sys_fifo_take_entry(&event_task->sched_lopri, sys_sched_entry_t, link))) {
	    sys_warning("lopri list: '%s'", e->name);
	    mem_drop(e);
	}
	sys_fifo_deinit(&event_task->sched);
	sys_fifo_deinit(&event_task->sched_lopri);
    }

    record_free(event_task);

    int32mt_dec(&MTE_ntask);
    return E_OK;
}

/* Returns a freeable string describing the current state of an event_task */
string_t
mte_event_task_fmt(sys_event_task_t const t)
{
    sys_time_t const now = NOW();
    return sys_sprintf(
		"%u %15s steps=%"PRIu64" age_sec=%"PRIu64" last_hb_ms_ago=%"PRIu64"%s%s%s"
		" active_polls=%u pending_alarms=%u queued_work=%u"
		" queued_work_lopri=%u epfd=%d wakeup_fd=%d",
		sys_thread_num(t->SYS), sys_thread_name(t->SYS), t->odometer,
		sys_time_delta_to_sec(now - t->dob),
		sys_time_delta_to_ms(now - t->heartbeat),
		t->is_engaged ? " ENGAGED" : " DISENGAGED",
		int32mt_get(&t->is_awake) ? "  AWAKE" : " IDLE",
		t->is_stopping ? " STOPPING" : "",
		int32mt_get(&t->npolls), sys_fifo_nitem(&t->alarm),
		sys_fifo_nitem(&t->sched), sys_fifo_nitem(&t->sched_lopri),
		t->epfd, t->wakeup_pe ? t->wakeup_pe->fd : -1);
}

/* Initialize the mte_event_task module (which can support multiple concurrent event threads) */
errno_t
mte_event_task_init(void)
{
    trace_init(true, false);
    assert_eq(int32mt_get(&MTE_ntask), 0);
    MTE_sched_cache = mem_cache_create("MTE_sched", sizeof(struct sys_sched_entry), MEM_ALIGN_MIN);
    MTE_alarm_cache = mem_cache_create("MTE_alarm", sizeof(struct sys_alarm_entry), MEM_ALIGN_MIN);
    MTE_poll_cache = mem_cache_create("MTE_poll", sizeof(struct sys_poll_entry), MEM_ALIGN_MIN);
    return E_OK;
}

errno_t
mte_event_task_exit(void)
{
    if (int32mt_get(&MTE_ntask) != 0) return EBUSY;

    mem_cache_destroy(MTE_sched_cache);
    mem_cache_destroy(MTE_alarm_cache);
    mem_cache_destroy(MTE_poll_cache);
    return E_OK;
}
