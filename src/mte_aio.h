/* sys_aio.h
 * Copyright 2015 David A. Butterfield
 * High-Performance Multi-Threaded Engine
 *
 * MT-callable asynchronous I/O (AIO) for files / block devices --
 * The functions in this file initiate I/O requests and are callable from any thread;
 * aio completions occur in sys_aio.c, initially on the aio thread (but the request's
 * closure may specify its handler to be scheduled on a different thread).
 */
#ifndef SYS_AIO_H
#define SYS_AIO_H

#include "mte_util.h"
#include "mte_mttypes.h"
#include "mte_mem.h"
#include <libaio.h>

//XXXX aio_closure hacked
struct sys_aio_op;
typedef struct { struct sys_thread * task; void (*fn)(void *, struct sys_aio_op *, errno_t); void * env; } aio_closure_t;
#define closure_is_none(c)		    ((c) == NULL || (c)->fn == NULL)
#define aio_tclosure(_task, _fn, _env)	    ((aio_closure_t){ .task = _task, .fn = _fn, .env = _env })
#define aio_closure_apply(name, c, op, err) ((c)->fn((c)->env, (op), (err)))
#define aio_closure_apply_or_schedule(name, closure, op, err) \
	    aio_closure_apply((name), (closure), (op), (err))

/* Configuration parameters for an aio instance (one open file or device) */
typedef struct sys_aio_cfg {
    count_t		qdepth;		/* max ops out to kernel at a time */
    count_t		qlowat;		/* when below qlowat submit batched ops out to kernel */
    count_t		max_ops_per_dispatch;	/* limit of aio completions per MTE schedule */
    sys_event_task_t	aio_task;	/* task to use for aio completions; NULL starts one */
    void	      (*thread_exit)(void *);
    void	      (*thread_init)(void *);
    void	      * thread_init_env;
} * sys_aio_cfg_t;

/* sys_aio_t manages one aio instance (one open file or block device) */
typedef struct sys_aio * sys_aio_t;

/* Wrap an aio instance around the given file descriptor */
extern sys_aio_t sys_aio_fopen(int fd, sys_aio_cfg_t const cfg, sstring_t const logname);

/* Frees the aio instance, but does not close the file-descriptor itself */
extern error_t sys_aio_close(sys_aio_t const aio);

/* Asynchronous file/disk (block device) I/O operation --
 * Embed one of these into a higher-level per-OP structure
 */
typedef struct sys_aio_op {
    sys_link_t		link;	    /* link in queue of ops awaiting io_submit */
    struct iocb		iocb;	    /* I/O control block { op, seekpos, addr, len } */
    aio_closure_t	closure;    /* fn(env, sys_aio_op, err) */
    size_t		size;	    /* total data bytes in the I/O request */
} * sys_aio_op_t;

#define SYS_AIO_MAX_IOV 1024	    /* max sg array entries per aio op */

/* Format a printable and freeable string describing the specified object */
string_t sys_aio_fmt(sys_aio_t const aio);
string_t sys_aio_op_fmt(sys_aio_t const aio, sys_aio_op_t const op);

#include "mte_aio_impl.h"   /* Implementation-private inline functions */

/**********
 * The functions below are callable from any thread to initiate I/O requests
 *
 * op is a pointer to scratch space for an op structure which will be initialized here.
 * Handlers for the closures passed to us here are called as handler(env, op, error_t)
 */

static inline void
sys_aio_readv(sys_aio_t aio, sys_aio_op_t op, aio_closure_t const * closure,
		uint64_t seekpos, size_t size, uint32_t niov, struct iovec * iov)
{
    assert(aio);
    assert(op);
    assert(!closure_is_none(closure));
    assert(IS_SECTOR_ALIGNED(seekpos));
    assert_gt(niov, 0);
    assert_le(niov, SYS_AIO_MAX_IOV);
    assert(iov);
    assert(!aio->closing);

    record_zero(op);
    op->closure = *closure;
    op->size = size;

    io_prep_preadv(&op->iocb, aio->file_fd, iov, niov, seekpos);
    _sys_aio_op(aio, op);

    int64mt_inc(&aio->nread);
    int64mt_add(&aio->nreadiov, niov);
}

static inline void
sys_aio_writev(sys_aio_t aio, sys_aio_op_t op, aio_closure_t const * closure,
		uint64_t seekpos, size_t size, uint32_t niov, struct iovec * iov)
{
    assert(aio);
    assert(op);
    assert(!closure_is_none(closure));
    assert(IS_SECTOR_ALIGNED(seekpos));
    assert_gt(niov, 0);
    assert_le(niov, SYS_AIO_MAX_IOV);
    assert(iov);
    assert(!aio->closing);

    record_zero(op);
    op->closure = *closure;
    op->size = size;

    io_prep_pwritev(&op->iocb, aio->file_fd, iov, niov, seekpos);
    _sys_aio_op(aio, op);

    int64mt_inc(&aio->nwrite);
    int64mt_add(&aio->nwriteiov, niov);
}

/* Start an fdsync op to flush cached writes to the aio's backing storage and notify after
 * persistent (on-disk) completion of pending writes.  Completion of the sync op only
 * guarantees persistent completion of write operations requested PRIOR to the sync request.
 * (It is not clear whether a write op occurring earlier in the same io_submit() batch as
 * a sync request is considered to be PRIOR to the sync request.)
 */
static inline void
sys_aio_sync(sys_aio_t const aio, sys_aio_op_t const op, aio_closure_t const * const closure)
{
    assert(aio);
    assert(op);
    assert(!closure_is_none(closure));
    assert(!aio->closing);

    record_zero(op);
    op->closure = *closure;

    io_prep_fdsync(&op->iocb, aio->file_fd);
    _sys_aio_op(aio, op);

    int64mt_inc(&aio->nsync);
}

#endif
