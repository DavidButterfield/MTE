/* mtelib_aio.c
 * Copyright 2016 David A. Butterfield
 * Multi-Threaded Engine async disk I/O services
 * Shim interfaces mapping aio_service API to MTE AIO service
 */
#define NAME AIO
#include "mtelib.h"
#include "mte_aio.h"

#include <fcntl.h>

typedef struct MTE_aio_service {
    struct aio_service_handle	AIOS_S;	  /* app-visible AIO Service handle */
    uint32_t			max_ops_outstanding;
    uint32_t			min_ops_outstanding;
    uint32_t			max_ops_per_dispatch;
    count_t			ninit;
    count_t			nfini;
    int32mt_t			nopen;
} * MTE_aio_service_t;

/* One aio instance per open file or block device */
typedef struct aio {
    struct aio_handle		AIO_S;	    /* aio handle structure */
    sys_aio_t			sys_aio;    /* MTE impl. sys_aio_handle */
    aio_closure_t		io_done;    /* precomputed completion closure */
    MTE_aio_service_t		aios;
    int				fd;
    bool			close_fd;
} * aio_t;

/* This structure is per-op private space preferably located in our caller's per-op structure */
typedef struct aio_op {
    struct sys_aio_op		sys_aio_op; /* scratch space for MTE sys_aio impl */
    void		     (* cb_fn)(void *, uintptr_t, error_t); /* op completion callback */
    void		      * cb_env;	    /* op completion callback arg */
    bool			free_me;    /* op was allocated here, not by caller */
} * aio_op_t;

static void
aio_done(void * const v_aio, sys_aio_op_t const sys_aio_op, errno_t const err)
{
    // aio_t const aio = v_aio;
    aio_op_t const op = enclosing_record(sys_aio_op, aio_op_t, sys_aio_op);
    bool const do_free = op->free_me;
    assert_is_bool(do_free);

    op->cb_fn(op->cb_env, (uintptr_t)sys_aio_op, err); /* invoke callback */
    /* Note that op may already no longer exist (in which case !do_free) */

    if (unlikely(do_free)) {
	record_free(op);
    }
}

static inline aio_op_t
op_setup(aio_op_t op, void (*fn)(void *, uintptr_t, error_t), void * env)
{
    assert(fn);

    if (likely(op)) {
	record_zero(op);
    } else {
	//XXX could use an aio_op_t cache
	op = record_alloc(op);	    /* op space not provided -- allocate it */
	op->free_me = true;
    }

    op->cb_fn = fn;
    op->cb_env = env;
    return op;
}

static inline void
iov_check(struct iovec * iov, uint32_t niov, size_t size)
{
#if defined(DEBUG) && DEBUG
    size_t total = 0;
    uint32_t iovn;
    for (iovn = 0; iovn < niov; iovn++) {
	assert(iov[iovn].iov_base);
	expect(iov[iovn].iov_len);
	total += iov[iovn].iov_len;
    }
    assert_eq(total, size);
#endif
}

static error_t
AIO_readv(aio_handle_t const AIO,
	     void * const private, void (*fn)(void *, uintptr_t, error_t), void * env,
	     uint64_t const diskpos, size_t size, uint32_t const niov, struct iovec * const iov)
{
    aio_t const aio = AIO->env;
    assert(niov);
    assert(iov);
    iov_check(iov, niov, size);

    aio_op_t const op = op_setup(private, fn, env);

    sys_aio_readv(aio->sys_aio, &op->sys_aio_op, &aio->io_done, diskpos, size, niov, iov);
    return 0;
}

static error_t
AIO_writev(aio_handle_t const AIO,
	     void * const private, void (*fn)(void *, uintptr_t, error_t), void * env,
	     uint64_t const diskpos, size_t size, uint32_t const niov, struct iovec * const iov)
{
    aio_t const aio = AIO->env;
    assert(niov);
    assert(iov);
    iov_check(iov, niov, size);

    aio_op_t const op = op_setup(private, fn, env);

    sys_aio_writev(aio->sys_aio, &op->sys_aio_op, &aio->io_done, diskpos, size, niov, iov);
    return 0;
}

static error_t
AIO_sync(aio_handle_t const AIO, void * const private,
				 void (*fn)(void *, uintptr_t, error_t), void * env)
{
    aio_t const aio = AIO->env;
    aio_op_t const op = op_setup(private, fn, env);

    sys_aio_sync(aio->sys_aio, &op->sys_aio_op, &aio->io_done);
    return 0;
}

static char const *
AIO_fmt(aio_handle_t const AIO)
{
    aio_t const aio = AIO->env;
    if (!aio->sys_aio) return NULL;

    return sys_aio_fmt(aio->sys_aio);
}

static void
AIO_close(aio_handle_t const AIO)
{
    aio_t const aio = AIO->env;
    sys_aio_close(aio->sys_aio);
    if (aio->close_fd) {
	int rc;
	RETRY_EINTR(rc, close(aio->fd));
    }
    int32mt_dec(&aio->aios->nopen);
    record_free(aio);
}

static struct aio_ops const MTE_AIO_ops = {
    .readv_start	= AIO_readv,
    .writev_start	= AIO_writev,
    .sync_start		= AIO_sync,
    .close		= AIO_close,
    .fmt		= AIO_fmt,
};

extern void aios_thread_init(void * unused);
extern void aios_thread_exit(void * unused);

static aio_handle_t
AIO_fopen(aio_service_handle_t const AIOS, int fd, uint64_t * p_nbytes, sstring_t logname)
{
    MTE_aio_service_t const aios = AIOS->env;
    struct sys_aio_cfg cfg = {
	.qdepth			= aios->max_ops_outstanding,
	.qlowat			= aios->min_ops_outstanding,
	.max_ops_per_dispatch	= aios->max_ops_per_dispatch,
	.aio_task		= NULL,	    /* NULL tells sys_aio to create one */
	.thread_exit		= aios_thread_exit,
	.thread_init		= aios_thread_init,
	.thread_init_env	= NULL,
    };

    sys_aio_t const sys_aio = sys_aio_fopen(fd, &cfg, logname);
    if (!sys_aio) return NULL;

    int32mt_inc(&aios->nopen);

    aio_t const aio = record_alloc(aio);
    aio->AIO_S.env = aio;
    aio->AIO_S.op = MTE_AIO_ops;
    aio->aios = aios;
    aio->fd = fd;
    aio->sys_aio = sys_aio;
    aio->io_done = aio_tclosure(aio->sys_aio->aio_thread, aio_done, aio);

    *p_nbytes = aio->sys_aio->nbytes;
    expect(*p_nbytes, "backing file size is zero");

    return &aio->AIO_S;
}

static aio_handle_t
AIO_open(aio_service_handle_t const AIOS, char const * const path, int const ro, uint64_t * p_nbytes)
{
    int flags = ro ? O_RDONLY : O_RDWR;
    flags |= O_LARGEFILE;
    flags |= O_NONBLOCK;
    flags |= O_NOATIME;     /* requires file ownership or privilege */

    int fd;
    do {
        fd = open(path, flags);
        if (fd < 0) {
            errno_t const err = errno;
            if (err == EPERM && (flags & O_NOATIME)) {
                flags &=~ O_NOATIME;
                sys_warning("AIO cannot open %s errno=%d (%s) -- retrying without O_NOATIME",
                                                            path, err, strerror(err));
                continue;
            }
            sys_warning("*** AIO cannot open %s errno=%d (%s) ***", path, err, strerror(err));
            return NULL;
        }
    } while (fd < 0);

    aio_handle_t ret = AIO_fopen(AIOS, fd, p_nbytes, path/*logname*/);

    if (ret) {
	aio_t aio = ret->env;
	aio->close_fd = true;
    }

    return ret;
}

static void
AIO_dump(aio_service_handle_t const AIOS)
{
}

static error_t
AIO_init(aio_service_handle_t const AIOS, void const * v_cfg)
{
    MTE_aio_service_t const aios = AIOS->env;
    if (aios->ninit > 0) return EINVAL;	    /* init MTR AIO service only once */

    ++aios->ninit;

    struct MTE_aio_service_cfg const * cfg = v_cfg;
    aios->max_ops_outstanding = cfg->max_ops_outstanding;
    aios->min_ops_outstanding = cfg->min_ops_outstanding;
    aios->max_ops_per_dispatch = cfg->max_ops_per_dispatch;

    return 0;
}

static error_t
AIO_fini(aio_service_handle_t const AIOS)
{
    MTE_aio_service_t const aios = AIOS->env;
    if (aios->nfini >= aios->ninit) return EINVAL;
    if (aios->nopen.i) return EBUSY;

    ++aios->nfini;
    return 0;
}

/* You can get and use more than one of these, but usually only one is needed */
aio_service_handle_t
MTE_aio_service_get(void)
{
    MTE_aio_service_t const aios = record_alloc(aios);
    aio_service_handle_t const AIOS = &aios->AIOS_S;
    AIOS->op_private_bytes = sizeof(struct aio_op);
    AIOS->env = aios;
    AIOS->op.init = AIO_init;
    AIOS->op.fini = AIO_fini;
    AIOS->op.dump = AIO_dump;
    AIOS->op.open = AIO_open;
    AIOS->op.fopen = AIO_fopen;
    return AIOS;
}

error_t
MTE_aio_service_put(aio_service_handle_t const AIOS)
{
    MTE_aio_service_t const aios = AIOS->env;
    if (aios->nfini < aios->ninit) return EBUSY;

    record_free(aios);
    return 0;
}
