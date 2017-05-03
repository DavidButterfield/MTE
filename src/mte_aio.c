/* sys_aio.c
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Asynchronous I/O for files / block devices
 */
#define NAME SYS_AIO
#include "mte_aio.h"
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/fs.h>		/* for BLKGETSIZE */

#define MAX_OPS_OUT_DEFAULT	256 /* TUNE MAX concurrent io_submitted I/O requests per aio */

/* Return a string describing the specified aio instance */
string_t
sys_aio_fmt(sys_aio_t const aio)
{
    uint32_t const avg_ops_per_submit = DIV32(aio->nops_completed, aio->nsubmit.i);
    uint32_t const avg_ops_per_event  = DIV32(aio->nops_completed, aio->nevent_cb);
    return string_concat_free(
	    sys_sprintf(
		"\tname:%s fd=%u event_fd=%u"
		" max_ops_out=%u ops_wake_lowat=%u IO: submit_checks=%"PRIu64" submits=%"PRIu64
		" io_events=%u nevent_nothing=%u"
		"\n\t"
		" nevent_ops_pending=%u nresched=%u ops_out/hiwat=%u/%u"
		" ops_requested=%"PRIu64" ops_completed=%"PRIu64" avg_ops/submit=%u"
		" avg_ops/event=%u "SYS_SPIN_FMT
		"\n\t"
		" read_ops=%"PRIu64" avg_read_niov=%u"
		" write_ops=%"PRIu64" avg_write_niov=%u sync_ops=%"PRIu64
		"\n\t mwq: ",
		aio->name, aio->file_fd, aio->event_fd,
		aio->max_ops_out, aio->min_ops_out, aio->nsubmit_checks.i, aio->nsubmit.i,
		aio->nevent_cb, aio->nevent_nothing, aio->nevent_pending, aio->nresched, aio->nops_out.i,
		aio->hiops_out.i, aio->nops_requested.i, aio->nops_completed, avg_ops_per_submit,
		avg_ops_per_event, SYS_SPIN_FIELDS(&aio->lock),
		aio->nread.i, DIV32(aio->nreadiov.i, aio->nread.i),
		aio->nwrite.i, DIV32(aio->nwriteiov.i, aio->nwrite.i), aio->nsync.i),
	    sys_mwqueue_stats(&aio->io_batch));
}

/* Return a string describing the specified aio op */
string_t
sys_aio_op_fmt(sys_aio_t const aio, sys_aio_op_t const op)
{
    sstring_t const op_str =
	op->iocb.aio_lio_opcode == IO_CMD_PREAD   ? "READ" :
	op->iocb.aio_lio_opcode == IO_CMD_PWRITE  ? "WRITE" :
	op->iocb.aio_lio_opcode == IO_CMD_FSYNC   ? "FSYNC" :
	op->iocb.aio_lio_opcode == IO_CMD_FDSYNC  ? "FDSYNC" :
	op->iocb.aio_lio_opcode == IO_CMD_NOOP    ? "NOP" :
	op->iocb.aio_lio_opcode == IO_CMD_PREADV  ? "PREADV" :
	op->iocb.aio_lio_opcode == IO_CMD_PWRITEV ? "PWRITEV" : "OP_UNKNOWN";

    if (op->iocb.aio_lio_opcode == IO_CMD_FSYNC)
	return sys_sprintf("aio[%s:%u:%u] %s", aio->name, aio->file_fd, aio->event_fd, op_str);
    else
	return sys_sprintf("aio[%s:f%u:e%u] %s seek=%llu iov=%p niov=%u",
			   aio->name, aio->file_fd, aio->event_fd,
			   op_str, op->iocb.u.v.offset, op->iocb.u.v.vec, op->iocb.u.v.nr);
}

/* Receive and process AIO completion events */
static void
sys_aio_event_handler(void * v_aio, uintptr_t u_events, errno_t err)
{
    assert_eq(err, E_OK);
    sys_aio_t const aio = v_aio;
    sys_aio_check_ontask(aio);

    ++aio->nevent_cb;

    /* read the number of aio ops completed since the last time through here */
    int64_t nevent_new = sys_eventfd_read(aio->event_fd);
    verify_rc(nevent_new, sys_eventfd_read, "aio={%s}", sys_aio_fmt(aio));

    /* accumulate number of aio's completed but not yet reaped */
    aio->nevent_pending += nevent_new;

    trace_verbose("nevent_new=%u nevent_pending=%u", (uint32_t)nevent_new, aio->nevent_pending);
    if (!aio->nevent_pending) {
	++aio->nevent_nothing;
	return;		/* no completed-but-unreaped aio's */
    }

    /* reap up to (max_ops_per_dispatch) pending completion events */
    count_t const nevent_to_reap = MIN(aio->max_ops_per_dispatch, aio->nevent_pending);
    struct io_event event_buf[nevent_to_reap];
    struct timespec timeout = { 0, 0 }; /* do not wait for events to occur */
    int rc;
    RETRY_EINTR(rc, io_getevents(aio->ctx, 1, NELEM(event_buf), event_buf, &timeout));
    if (rc < 0) sys_breakpoint();
    verify_rc(nevent_new, io_getevents, "aio={%s}", sys_aio_fmt(aio));

    count_t const nevent_reaped = rc;
    assert_be(nevent_reaped, nevent_to_reap);
    expect_eq(nevent_reaped, nevent_to_reap);

    aio->nevent_pending -= nevent_reaped;
    if (aio->nevent_pending) {
	expect(nevent_reaped);
	/* Schedule to come back to continue work we are not going to complete this call --
	 * leaving this function with nevent_pending implies we're expecting to be called
	 * back by the closure we schedule here.
	 */
	++aio->nresched;
	sys_callback_schedule(aio->aio_task, sys_aio_event_handler, aio, u_events, E_OK);
    }

    if (!nevent_reaped) return;

    /* We have all our results for this call to the event_handler in local variables,
     * so we can now allow writers visibility to the newly-available op slots.
     */
    int32_t const nops_out = int32mt_sub(&aio->nops_out, nevent_reaped);
    assert_ge(nops_out, 0);

    /* Process the reaped disk I/O completion events */
    idx_t eventn;
    for (eventn = 0; eventn < nevent_reaped; eventn++) {
	struct io_event * const event = &event_buf[eventn];
	assert_eq(event->data, aio);
	struct iocb * const iocb = event->obj;
	sys_aio_op_t op = enclosing_record(iocb, sys_aio_op_t, iocb);

	if (event->res != op->size) {
	    string_t const op_str = sys_aio_op_fmt(aio, op);
	    sys_warning("AIO ERROR: OP={%s} size=%ld res=%ld res2=%ld",
			op_str, op->size, event->res, event->res2);
	    string_free(op_str);
	    err = EIO;
	} else {
	    expect_eq(event->res2, 0);
	    string_t op_str = NULL;
	    trace_verbose("AIO completion OP={%s}", op_str=sys_aio_op_fmt(aio, op));
	    string_free_null(op_str);
	}

	aio_closure_apply_or_schedule("aio_op_closure", &op->closure, op, err);
	++aio->nops_completed;
    }

       //XXX If considering moving this up above the delivery of completed
      //    events, consider also or instead increasing min_ops_outstanding.
     //
    /* We decreased nops_out; check whether more ops can be submitted */
    if ((unsigned)nops_out < aio->min_ops_out) {
	_sys_aio_queue_check_submit(aio);
    }

    trace_tooverbose("nops_completed=%lu", aio->nops_completed);
}

static void
close_finish(sys_aio_t const aio)
{
    assert(aio->closing);

    sys_mwqueue_deinit(&aio->io_batch);

    int rc = io_destroy(aio->ctx);
    expect_rc(rc, io_destroy);

    sys_poll_disable(aio->aio_task, aio->poll_entry);

    sys_eventfd_close(aio->event_fd);
    expect_rc(rc, close, "aio[%s]->event_fd (%d)", aio->name, aio->event_fd);

    if (aio->own_aio_task) {
	sys_event_task_stop(aio->aio_task);
    }

    string_free(aio->name);
    record_free(aio);
}

/* Close an aio instance -- caller must wait for outstanding I/O count zero before calling */
errno_t
sys_aio_close(sys_aio_t const aio)
{
    sys_aio_check(aio);
    assert(!aio->closing);

    /* These are expected because we make the caller responsible for waiting
     * until all I/O completes before calling.  XXX Could do the waiting here
     */
    expect_eq(aio->nops_out.i, 0, "aio is in progress");
    expect_eq(aio->nevent_pending, 0, "an event_handler closure is in-flight");
    expect_eq(aio->nops_completed, aio->nops_requested.i, "aio is queued");

    if (aio->nops_out.i) return EBUSY;
    if (aio->nevent_pending) return EBUSY;
    if (aio->nops_completed < (unsigned)aio->nops_requested.i) return EBUSY;

    sys_spin_lock(&aio->lock);

    aio->closing = true;

    if (!aio->engaged) {
	/* aio_open_ontask is still in-flight -- it will do the close_finish() */
	sys_spin_unlock(&aio->lock);
	return E_OK;
    }

    sys_spin_unlock(&aio->lock);
    close_finish(aio);
    return E_OK;
}

#define SYS_AIO_EVENT	(EPOLLIN)   /* level-triggered */

/* Finish the aio initialization on the aio thread */
static void
aio_open_ontask(void * v_aio, uintptr_t unused, errno_t err)
{
    assert_eq(err, E_OK);
    sys_aio_t const aio = v_aio;
    assert_this_thread_is(aio->aio_thread);

    sys_spin_lock(&aio->lock);

    if (aio->closing) {
	/* Somebody closed the aio *very* shortly after it was opened */
	sys_spin_unlock(&aio->lock);
	close_finish(aio);
	return;
    }

    /* Setting aio->engaged allows submitting threads into check_submit */
    aio->engaged = true;    /* this must be done before dropping the lock */

    sys_spin_unlock(&aio->lock);

    aio->poll_entry = sys_poll_enable(aio->aio_task, sys_aio_event_handler, aio,
				      aio->event_fd, SYS_AIO_EVENT, aio->name);

    sys_aio_check_ontask(aio);

    /* There could be ops already queued waiting for us to finish initing the aio task */
    _sys_aio_queue_check_submit(aio);	/* check for and submit them */
}

/* aio_thread runs aio_task event loop until the aio instance is closed */
static errno_t
aio_thread_fn(void * v_aio)
{
    sys_aio_t const aio = v_aio;
    sys_aio_check(aio);
    assert_this_thread_is(aio->aio_thread);
    trace_verbose("AIO: %s", aio->name);

    void * thread_init_env = aio->thread_init_env;
    void (*thread_exit)(void *) = aio->thread_exit;
    if (aio->thread_init) aio->thread_init(thread_init_env);

    /* Event loop returns when aio instance is closed and _task_stop() is called */
    errno_t ret = sys_event_task_run(aio->aio_task);
				/*** Note that aio probably no longer exists ***/
    expect_eq(ret, E_OK);

    if (thread_exit) thread_exit(thread_init_env);

    sys_event_task_free(this_event_task());
    sys_thread_exit(0);		/* no return */
}

/* Wrap an aio instance around the specified fd --
 * upon return our caller may begin submitting ops immediately.
 */

sys_aio_t
sys_aio_fopen(int fd, sys_aio_cfg_t const cfg, sstring_t const logname)
{
    struct stat statbuf;
    int rc = fstat(fd, &statbuf);
    if (rc < 0) {
	sys_warning("AIO fstat cannot determine device size %s errno=%d (%s)",
		    logname, errno, strerror(errno));
	return NULL;
    }

    /* compute the size of the backing storage */
    uint64_t backing_size = 0;

    if (S_ISREG(statbuf.st_mode)) {			    /* regular file */
	backing_size = statbuf.st_size;
    }
    else if (S_ISBLK(statbuf.st_mode)) {		    /* block device */
	uint64_t blk_cnt;
	ioctl(fd, BLKGETSIZE, &blk_cnt);
	backing_size = blk_cnt * 512;
    }
    else if (S_ISCHR(statbuf.st_mode)) {
	struct stat zero_statbuf;
	rc = stat("/dev/zero", &zero_statbuf);
	if (rc == 0 && statbuf.st_rdev == zero_statbuf.st_rdev) { /* /dev/zero */
	    backing_size = 1ull << 40;	/* 1 TB */
	}
    }

    sys_aio_t const aio = record_alloc(aio);
    aio->magic = SYS_AIO_MAGIC;
    aio->name = sstring_copy(logname);
    aio->file_fd = fd;
    aio->nbytes = backing_size;

    sys_notice("aio name=%s fd=%d size=%lx", aio->name, aio->file_fd, aio->nbytes);

    aio->min_ops_out = cfg->qlowat ?: 1;
    aio->max_ops_out = cfg->qdepth >= cfg->qlowat ? cfg->qdepth : cfg->qlowat;
    aio->max_ops_per_dispatch = cfg->max_ops_per_dispatch;
    aio->thread_exit = cfg->thread_exit;
    aio->thread_init = cfg->thread_init;
    aio->thread_init_env = cfg->thread_init_env;

    sys_spinlock_init(&aio->lock);
    sys_mwqueue_init(&aio->io_batch);

    rc = io_setup(aio->max_ops_out, &aio->ctx); /* initialize aio context */
    verify_rc(rc, io_setup, "aio={%s}", sys_aio_fmt(aio));

    aio->event_fd = sys_eventfd_create("aio");

    sys_aio_check(aio);

    /* If cfg->aio_task is NULL we create a new thread to handle aio events;
     * otherwise the aio_task passed in the config will handle aio events
     * (its thread having been arranged elsewhere).
     */
    if (cfg->aio_task) {
	aio->aio_task = cfg->aio_task;
	sys_callback_schedule(aio->aio_task, aio_open_ontask, aio, 0, E_OK);
    } else {
	aio->own_aio_task = true;   /* remember to free the task/thread later */

	struct sys_event_task_cfg et_cfg = {
	    .max_polls = 32,
	    .max_steps = 100,
	};
	aio->aio_task = sys_event_task_alloc(&et_cfg);

	/* First thing to do out of the event loop when it starts */
	sys_callback_schedule(aio->aio_task, aio_open_ontask, aio, 0, E_OK);

	aio->aio_thread = sys_thread_alloc(aio_thread_fn, aio, sstring_copy(logname));
	sys_thread_start(aio->aio_thread);
    }

    return aio;
}
