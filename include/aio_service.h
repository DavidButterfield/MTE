/* aio_service.h
 * API for an asynchronous disk I/O service
 * Copyright 2015 David A. Butterfield
 */
#ifndef AIO_SERVICE_H
#define AIO_SERVICE_H
#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <sys/uio.h>
#include <errno.h>

/* One aio_handle_t [AIO] for each open file/device */
typedef struct aio_handle * aio_handle_t;

/* Handle to an async file/block I/O service [AIOS] (normally one instance) */
typedef struct aio_service_handle * aio_service_handle_t;
typedef void * aio_service_cfg_t;	/* Implementor-specific */

/* Async disk I/O [AIO] ops */

/* PRIVATE must be NULL or a pointer to op-lifetime scratch space of size AIOS->op_private_bytes
 * for private use by the AIO implementation.  If NULL is passed the operation will incur an
 * extra memory alloc/free pair.
 */

#define aio_readv(AIO, PRIVATE, FN, ENV, SEEK, SIZE, NIOV, IOV)	\
	((AIO)->op.readv_start(	(AIO), (PRIVATE), (FN), (ENV), (SEEK), (SIZE), (NIOV), (IOV) ))

#define aio_writev(AIO, PRIVATE, FN, ENV, SEEK, SIZE, NIOV, IOV)	\
	((AIO)->op.writev_start((AIO), (PRIVATE), (FN), (ENV), (SEEK), (SIZE), (NIOV), (IOV) ))

#define aio_sync(AIO, PRIVATE, FN, ENV)	\
	((AIO)->op.sync_start(  (AIO), (PRIVATE), (FN), (ENV)				     ))

#define aio_fmt(AIO)			((AIO)->op.fmt(		(AIO)			     ))

/* If aio instance opened with aio_open (NOT with aio_fopen), then file descripter is closed */
#define aio_close(AIO)			((AIO)->op.close(	(AIO)			     ))

struct aio_handle {
    void	     * env;		/* Implementor per-open-file private */
    struct aio_ops {
	error_t	(*readv_start) (aio_handle_t,
				   void *, void (*fn)(void *, uintptr_t, error_t), void * env,
				   uint64_t, size_t,  uint32_t, struct iovec *);
	error_t	(*writev_start)(aio_handle_t,
				   void *, void (*fn)(void *, uintptr_t, error_t), void * env,
			           uint64_t, size_t,  uint32_t, struct iovec *);
	error_t	(*sync_start)     (aio_handle_t,
				   void *, void (*fn)(void *, uintptr_t, error_t), void * env);
	void	(*close)          (aio_handle_t);
	char const * (*fmt)	  (aio_handle_t);   /* caller to free using sys_mem_free */
    } op;
};

/* Async disk service [AIOS] ops */

/* Open a new file descriptor and wrap it with a new aio instance */
#define aio_open(AIOS, PATH, RO, SIZEP)	    ((AIOS)->op.open( (AIOS), (PATH), (RO), (SIZEP) ))

/* Wrap an already-open file descriptor with a new aio instance */
#define aio_fopen(AIOS, FD, SIZEP, LOGNAME) ((AIOS)->op.fopen((AIOS), (FD), (SIZEP), (LOGNAME) ))

#define aio_service_init(AIOS, CFG)	((AIOS)->op.init( (AIOS), (CFG)	))
#define aio_service_fini(AIOS)		((AIOS)->op.fini( (AIOS)	))
#define aio_service_dump(AIOS)		((AIOS)->op.dump( (AIOS)	))

struct aio_service_handle {
    void	      * env;		    /* AIO service Implementor private */
    uint32_t		op_private_bytes;   /* Space requested for AIO per-op private area */
    struct aio_service_ops {
	error_t	      (*init) (aio_service_handle_t, void const *);
	error_t	      (*fini) (aio_service_handle_t);
	void	      (*dump) (aio_service_handle_t);
	aio_handle_t  (*open) (aio_service_handle_t, char const * path, int ro, uint64_t *);
	aio_handle_t  (*fopen)(aio_service_handle_t, int fd, uint64_t *, char const * logname);
    } op;
};

#endif /* AIO_SERVICE_H */
