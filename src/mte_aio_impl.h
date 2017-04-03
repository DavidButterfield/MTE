#ifndef SYS_AIO_H
#error sys_aio_impl.h should only be #included from sys_aio.h
#endif
/* sys_aio_impl.h
 * Copyright 2015 David A. Butterfield
 * High-Performance Multi-Threaded Engine
 *
 * MT-callable asynchronous I/O (AIO) for files / block devices --
 * implementation private declarations
 */
#ifndef SYS_AIO_IMPL_H
#define SYS_AIO_IMPL_H
#include <x86_64-linux-gnu/sys/eventfd.h>

/* One struct sys_aio for each file or block device open for async I/O */
typedef struct sys_aio {
	    /* fields unchanging after initialization */
    magic_t		magic;		    /* integrity check */
    int			file_fd;	    /* open data file descriptor */
    int			event_fd;	    /* async I/O completion event fd */
    count_t		min_ops_out;	    /* io_submit when < min_ops_out to kernel */
    count_t		max_ops_out;	    /* maximum number of incomplete io_submitted ops */
    count_t		max_ops_per_dispatch;	/* max number of completions per dispatch */
    uint64_t		nbytes;		    /* size of medium or backing file */
    string_t	        name;		    /* name of backing store data file or device */
    sys_event_task_t	aio_task;	    /* task receiving I/O completions -- for checking */
    sys_thread_t	aio_thread;	    /* thread running aio_task event task, if owned */
    bool		own_aio_task;	    /* we created the aio task (wasn't passed in) */
    io_context_t 	ctx;		    /* async I/O context */
    sys_poll_entry_t	poll_entry;	    /* event fd poll entry */
    void              (*thread_exit)(void *);
    void              (*thread_init)(void *);
    void	      * thread_init_env;
 
	    /* dynamic state */
    sys_mwqueue_t	io_batch;	    /* requested ops not yet passed to io_submit */
    count_t		nevent_pending;	    /* ops reported done, but not yet reaped */
    int32mt_t		nops_out;	    /* ops passed to io_submit, but not yet reaped */
    bool       volatile engaged;	    /* thread has completed initialization */
    bool       volatile closing;	    /* inter-thread close protocol in progress */
 
	    /* statistics */
    int64mt_t		nops_requested;	    /* ops requested of sys_aio */
    int64mt_t		nsubmit_checks;     /* number of io_submit(2) checks */
    int64mt_t		nsubmit;	    /* number of io_submit(2) calls */
    int32mt_t		hiops_out;	    /* high-watermark of nops_out */
    count_t		nresched;	    /* number of event_handler reschedules */
    count_t		nevent_cb;	    /* number of calls to event_handler */
    count_t		nevent_nothing;	    /* event_handler calls with no events */
    lcount_t		nops_completed;	    /* ops completed back to originators */

    int64mt_t		nread;		    /* read ops requested */
    int64mt_t		nwrite;		    /* write ops requested */
    int64mt_t		nsync;		    /* sync ops requested */
    int64mt_t		nreadiov;	    /* aggregate read niov (for averaging) */
    int64mt_t		nwriteiov;	    /* aggregate write niov */

    CACHE_ALIGNED
    sys_spinlock_t	lock;		    /* serialize _sys_aio_queue_check_submit */
} * sys_aio_t;

#define SYS_AIO_MAGIC 0xA10A10		    /* "AIO AIO" */

/* Call sys_aio_check from any task */
static inline void
sys_aio_check(sys_aio_t const aio)
{
    mem_check(aio);
    assert_eq(aio->magic, SYS_AIO_MAGIC);
    assert(aio->name);
    assert_ae(aio->min_ops_out, 1);
    assert_be(aio->min_ops_out, aio->max_ops_out);
    assert_ge(aio->nops_out.i, 0);
    assert_le((unsigned)aio->nops_out.i, aio->max_ops_out);
    assert_ae(aio->max_ops_per_dispatch, 1);
    assert_be(aio->nsubmit.i, aio->nsubmit_checks.i);
}

/* Call sys_aio_check_ontask from aio task only */
static inline void
sys_aio_check_ontask(sys_aio_t const aio)
{
    sys_aio_check(aio);

    assert_this_event_task_is(aio->aio_task);
    assert_this_thread_is(aio->aio_thread);

    assert(aio->ctx);

    assert_be(aio->nresched, aio->nevent_cb);
    assert_be(aio->nevent_cb, aio->nops_completed);
    assert_be(aio->nevent_nothing, aio->nevent_cb);
    assert_be(aio->nevent_cb - aio->nevent_nothing, aio->nops_completed);
    assert_be(aio->nevent_pending, aio->nops_out.i);
    assert_be(aio->nops_completed, aio->nops_requested.i);
}

/* Call from any thread to possibly io_submit more ops */
static inline void
_sys_aio_queue_check_submit(sys_aio_t const aio)
{
    struct iocb * submit_op[aio->max_ops_out];
    int32_t nops_out = 0;
    long nops_submit = 0;

    /* Only one thread in here at a time per file trying to submit I/O requests to the kernel */
    sys_spin_lock(&aio->lock);
    do {
	/* Get the number of ops presently outstanding to io_submit --
	 * that number cannot *increase* unexpectedly while we are holding aio->lock,
	 * because here is the only place anywhere in the code that *increases* nops_out
	 */
	nops_out = int32mt_get(&aio->nops_out);
	assert_ge(nops_out, 0);
	assert_be((unsigned)nops_out, aio->max_ops_out);

	/* If we already have enough outstanding ops, defer submitting more */
	if (likely((unsigned)nops_out >= aio->min_ops_out)) break;

	/* Compute the maximum (additional) ops we can io_submit at the moment */
	count_t const avail_slots = aio->max_ops_out - nops_out;

	/* Stage the iocb pointers of up to avail_slots ops into submit_op for io_submit */
	for (nops_submit = 0; nops_submit < avail_slots; nops_submit++) {
	    sys_aio_op_t const op = sys_mwqueue_take_entry(&aio->io_batch, sys_aio_op_t, link);
	    if (unlikely(!op)) break;		/* exhausted all queued requests */

	    /* event_handler will run on the aio_thread (gets the event_fd notifications) */
	    assert(aio->aio_task);
	    io_set_eventfd(&op->iocb, aio->event_fd);
	    op->iocb.data = aio;
	    submit_op[nops_submit] = &op->iocb;
	    string_t op_str = NULL;
	    trace_verbose("AIO submit OP={%s}", op_str=sys_aio_op_fmt(aio, op));
	    string_free_null(op_str);
	}

	/* Claim nops_submit of the available slots */
	nops_out = int32mt_add(&aio->nops_out, nops_submit);

    } while (0);
    sys_spin_unlock(&aio->lock);

    assert_be((unsigned)nops_out, aio->max_ops_out);

    int64mt_inc(&aio->nsubmit_checks);

    if (unlikely(nops_submit == 0)) {
	return;
    }

    /* stats only; need not be consistent with other values set above under lock */
    int64mt_inc(&aio->nsubmit);
    int32mt_hiwat(&aio->hiops_out, nops_out);

    /* We want to do the io_submit system call here outside of the lock --
     * While under lock we claimed nops_submit of the max_ops_out maximum for nops_out; so even
     * if another thread comes in here and finds more ops on the io_batch queue and io_submits
     * ahead of us, it won't cause us to have more ops out to io_submit than we're allowed at a
     * time.  Also under the lock, we already took the ops we're going to io_submit off the mwq
     * and into our local submit_op array.
     *
     * XXXXX Ugh, but it could reorder a sync op ahead of prior write ops... FIX!
     */
    int const rc = io_submit(aio->ctx, nops_submit, submit_op);

    verify_rc(rc, io_submit, "io_submit(%p, %ld, %p) failed on\n    aio={%s}: %s",
			     aio->ctx, nops_submit, submit_op, sys_aio_fmt(aio),
			     rc < 0 ? strerror(-rc) : "");
    assert_eq(rc, nops_submit);
}

/* Accept an I/O request, and possibly io_submit(2) an accumulated batch of such requests --
 * call from any thread
 */
static inline void
_sys_aio_op(sys_aio_t const aio, sys_aio_op_t const op)
{
    sys_aio_check(aio);
    assert(!aio->closing);

    int64mt_inc(&aio->nops_requested);

    string_t str = NULL;
    trace_tooverbose("request OP={%s}", str=sys_aio_op_fmt(aio, op));
    string_free_null(str);

    /* Add our op to the queue of ops being accumulated for batch io_submit */
    sys_mwqueue_append(&aio->io_batch, &op->link);

    /* If there are ops outstanding, then we are expecting a completion to
     * sys_aio_event_handler, which will call _sys_aio_queue_check_submit as needed.
     * If no ops are outstanding, we get things started right here (if the aio_task
     * is ready).
     */
    if (unlikely(int32mt_get(&aio->nops_out) == 0) && likely(aio->engaged)) {
	_sys_aio_queue_check_submit(aio);
    }
}

#endif /* SYS_AIO_IMPL_H */
