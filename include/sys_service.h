/* sys_service.h
 * Copyright 2015 David A. Butterfield
 * Interface to system and event services:  memory, time, timers, threads, polling, etc
 */
#ifndef SYS_SERVICE_H
#define SYS_SERVICE_H
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
#include <sys/epoll.h>
#include <execinfo.h>
#include <sys/syscall.h>

typedef const char		      * sstring_t;	    /* unowned or static string */

typedef uint64_t			sys_time_t;	    /* monotonically-increasing time */
typedef uint64_t			sys_time_delta_t;   /* time interval in ns */

typedef void *				sys_service_cfg_t;  /* sys_service provider dependent */
typedef struct sys_service_handle     * sys_service_handle_t;

typedef struct sys_buf_cache	      * sys_buf_cache_t;    /* cache of refcounted buffers */
typedef struct sys_buf		      * sys_buf_t;	    /* refcounted buffer */

typedef struct sys_thread	      * sys_thread_t;
typedef struct sys_event_task	      * sys_event_task_t;

typedef struct sys_sched_entry	      * sys_sched_entry_t;  /* callback in sequence ASAP */
typedef struct sys_alarm_entry	      * sys_alarm_entry_t;  /* callback at expire time */
typedef struct sys_poll_entry	      * sys_poll_entry_t;   /* callback when socket ready */

typedef struct sys_event_task_cfg {
    uint32_t		    max_polls;	    /* max fds to process per poll check */
    uint32_t		    max_steps;	    /* max sched callbacks before rechecking polls */
} * sys_event_task_cfg_t;

/* OP vector for system service provider */
struct sys_service_handle {
    void	        * env;		/* system service Implementor private */
    struct sys_service_ops {
	error_t	        (*SS_init)(sys_service_cfg_t);
	error_t	        (*SS_fini)(void);
	void	        (*SS_dump)(sstring_t reason);
	void	        (*SS_backtrace)(sstring_t reason);
	void __attribute__((__noreturn__))
			(*SS_abort)(void);	    /* does dump and backtrace */

	sys_time_t      (*SS_time_now)(void);	    /* ns granularity */

	/* General memory allocation ops */
	void	      * (*SS_mem_alloc)(size_t, sstring_t whence);
	void	      * (*SS_mem_zalloc)(size_t, sstring_t whence);
	void	      * (*SS_mem_realloc)(void *, size_t, sstring_t whence);
	void	        (*SS_mem_free)(void const *, sstring_t whence);

	/* Buffer cache ops and refcounted buffer ops */
	sys_buf_cache_t	(*SS_buf_cache_create)(sstring_t name, size_t, size_t align);

	error_t		(*BUF_cache_destroy)(sys_buf_cache_t);
	sys_buf_t	(*BUF_alloc)(sys_buf_cache_t, sstring_t whence);
	sys_buf_t	(*BUF_zalloc)(sys_buf_cache_t, sstring_t whence);

	void		(*BUF_hold)(sys_buf_t, sstring_t whence);
	void		(*BUF_drop)(sys_buf_t, sstring_t whence);
	void		(*BUF_check)(sys_buf_t);

	/* Thread ops */
	sys_thread_t    (*SS_thread_alloc)(error_t (*fn)(void *), void * env, char * name);

	error_t		(*THREAD_start)(sys_thread_t);
	void		(*THREAD_exit)(long rc) __attribute__((__noreturn__));
	void		(*THREAD_free)(sys_thread_t);	/* not to be called from on-thread */

	/* Event thread ops */
	sys_event_task_t   (*SS_etask_alloc)(struct sys_event_task_cfg *);

	char *		(*ETASK_fmt)(sys_event_task_t);	/* freeable status/stats string */
	error_t	        (*ETASK_run)(sys_event_task_t);
	error_t	        (*ETASK_stop)(sys_event_task_t);
	error_t	        (*ETASK_free)(sys_event_task_t);

	/* Polls, alarms, and scheduled callbacks:  upon return from its delivery handler (fn),
	 * an entry becomes invalid, but its handle may still be passed to the appropriate
	 * cancel function where the cancel/deliver race is detected.  Cancel function returns
	 * 0 if entry found and removed, EINVAL if entry not found (presumably delivered).
	 */
	sys_poll_entry_t (*ETASK_poll_enable)(sys_event_task_t,
			    void (*fn)(void *, uintptr_t, error_t), void * env,
			    int fd, unsigned long events, sstring_t name);

	void		(*ETASK_poll_disable_sync)(sys_event_task_t, sys_poll_entry_t);

	sys_alarm_entry_t (*ETASK_alarm_set)(sys_event_task_t,
			    void (*)(void *, uintptr_t, error_t), void *,
			    sys_time_t, sstring_t name);

	error_t (*ETASK_alarm_cancel_sync)(sys_event_task_t, sys_alarm_entry_t);

	sys_sched_entry_t (*ETASK_callback_schedule)(sys_event_task_t,
			    void (*cb_fn)(void * env, uintptr_t arg, error_t),
			    void * cb_env, uintptr_t cb_arg, error_t, sstring_t name);

	error_t (*ETASK_callback_cancel_sync)(sys_event_task_t, sys_sched_entry_t);

	sys_sched_entry_t (*ETASK_callback_schedule_lopri)(sys_event_task_t,
			    void (*cb_fn)(void * env, uintptr_t arg, error_t),
			    void * cb_env, uintptr_t cb_arg, error_t, sstring_t name);

	error_t (*ETASK_callback_cancel_lopri_sync)(sys_event_task_t, sys_sched_entry_t);
    } op;
};

/* Common storage for sys_service provider handle */
extern sys_service_handle_t		SYS_SERVICE; 

/* Install (or NULLify) a sys_service provider */
#define sys_service_set(handle)	       (SYS_SERVICE = (handle))

/* System Services */

#define sys_service_init(CFG) (SYS_SERVICE->op.SS_init ? SYS_SERVICE->op.SS_init(CFG) : 0)
#define sys_service_fini()    (SYS_SERVICE->op.SS_fini ? SYS_SERVICE->op.SS_fini()    : 0)

#define sys_dump(reason)		(SYS_SERVICE->op.SS_dump(reason))
#define sys_abort()			(SYS_SERVICE->op.SS_abort())

#define sys_backtrace(fmtargs...) _sys_backtrace(""fmtargs)
#define _sys_backtrace(fmt, args...) \
do { \
    char * _str; \
    int _ret = asprintf(&_str, fmt, ##args); \
    if (_ret < 0) \
	_str = NULL; \
    SYS_SERVICE->op.SS_backtrace(_str); \
    if (_str) \
	free(_str); \
} while (0)

/* Memory */

#define sys_mem_alloc(SZ)		(SYS_SERVICE->op.SS_mem_alloc(		(SZ), FL_STR  ))
#define sys_mem_zalloc(SZ)		(SYS_SERVICE->op.SS_mem_zalloc(		(SZ), FL_STR  ))
#define sys_mem_realloc(BUF, SZ)	(SYS_SERVICE->op.SS_mem_realloc( (BUF), (SZ), FL_STR  ))
#define sys_mem_free(BUF)		(SYS_SERVICE->op.SS_mem_free(    (BUF),	      FL_STR  ))

#define sys_mem_dup(addr, len)		memcpy(sys_mem_alloc(len), (addr), (len))

#define sys_buf_cache_create(NM, SIZE, ALIGN) \
					(SYS_SERVICE->op.SS_buf_cache_create((NM), (SIZE), (ALIGN) ))
#define sys_buf_cache_destroy(CACHE)	(SYS_SERVICE->op.BUF_cache_destroy(CACHE))

#define sys_buf_alloc(CACHE)		(SYS_SERVICE->op.BUF_alloc( (CACHE),	      FL_STR  ))
#define sys_buf_zalloc(CACHE)		(SYS_SERVICE->op.BUF_zalloc((CACHE),	      FL_STR  ))

#define sys_buf_hold(BUF)		(SYS_SERVICE->op.BUF_hold(       (BUF),       FL_STR  ))
#define sys_buf_drop(BUF)		(SYS_SERVICE->op.BUF_drop(	 (BUF),       FL_STR  ))
#define sys_buf_free(BUF)		(SYS_SERVICE->op.BUF_drop(	 (BUF),       FL_STR  ))
#define sys_buf_check(BUF)		(SYS_SERVICE->op.BUF_check(	 (BUF)	  	      ))

#define BYTES8(byte)			((byte) * 0x0101010101010101UL)

#define MEM_PATTERN_ALLOC		0xd5U
#define MEM_ZAP				0xb9U

#define MEM_PATTERN_ALLOC_64		BYTES8(MEM_PATTERN_ALLOC)
#define MEM_ZAP_64			BYTES8(MEM_ZAP)

/* Time */
					/* nanoseconds since (last reboot or similar timebase) */
#define sys_time_now()			(SYS_SERVICE->op.SS_time_now())
#define sys_time_hz()			sys_time_delta_of_sec(1)

#define sys_time_zero()			((sys_time_t)(0))
#define sys_time_invalid()		((sys_time_t)(-1))
#define sys_time_is_invalid(t)		((t) == sys_time_invalid())

#define sys_time_delta_zero()		((sys_time_delta_t)(0))

#define sys_time_delta_of_ns(t)		(t) /* sys_time_delta_t is ns granularity */
#define sys_time_delta_of_us(t)		((t) * sys_time_delta_of_ns(1000L))
#define sys_time_delta_of_ms(t)		((t) * sys_time_delta_of_us(1000L))
#define sys_time_delta_of_sec(t)	((t) * sys_time_delta_of_ms(1000L))
#define sys_time_delta_of_min(t)	((t) * sys_time_delta_of_sec(60L))
#define sys_time_delta_of_hour(t)	((t) * sys_time_delta_of_min(60L))
#define sys_time_delta_of_day(t)	((t) * sys_time_delta_of_hour(24L))

#define sys_time_delta_to_us(delta)	((delta) / sys_time_delta_of_us(1))
#define sys_time_delta_to_ms(delta)	((delta) / sys_time_delta_of_ms(1))
#define sys_time_delta_to_sec(delta)	((delta) / sys_time_delta_of_sec(1))
#define sys_time_delta_mod_sec(delta)	((delta) % sys_time_delta_of_sec(1))

#define SYS_TIME_DELTA_FMT		"%"PRIu64".%09"PRIu64	/* s.mmmuuunnn */
#define SYS_TIME_DELTA_FIELDS(t)	sys_time_delta_to_sec(t), sys_time_delta_mod_sec(t)

#define SYS_TIME_DELTA_FMT_us		"%"PRIu64".%06"PRIu64	/* s.mmmuuu */
#define SYS_TIME_DELTA_FIELDS_us(t)	sys_time_delta_to_sec(t), (sys_time_delta_mod_sec(t)/1000L)

#define SYS_TIME_DELTA_FMT_us2		"%2"PRIu64".%06"PRIu64	/* ss.mmmuuu */
#define SYS_TIME_DELTA_FIELDS_us(t)	sys_time_delta_to_sec(t), (sys_time_delta_mod_sec(t)/1000L)

/* Threads */

#define sys_thread_alloc(FN, ENV, NM)	(SYS_SERVICE->op.SS_thread_alloc((FN), (ENV), (NM)))
#define sys_thread_start(THREAD)	(SYS_SERVICE->op.THREAD_start(THREAD))
#define sys_thread_free(THREAD)		(SYS_SERVICE->op.THREAD_free(THREAD))

//XXX Should take a long argument
static inline void __attribute__((__noreturn__))
sys_thread_exit(long rc)
{
    void (*THREAD_exit)(long) __attribute__((__noreturn__)) = SYS_SERVICE->op.THREAD_exit;
    THREAD_exit(rc);
}

#define sys_event_task_alloc(CFG)	(SYS_SERVICE->op.SS_etask_alloc(CFG))
#define sys_event_task_fmt(ETASK)	(SYS_SERVICE->op.ETASK_fmt(ETASK))
#define sys_event_task_free(ETASK)	(SYS_SERVICE->op.ETASK_free(ETASK))

/* sys_event_task_run() does not return until sys_event_task_stop() is called */
#define sys_event_task_run(ETASK)	(SYS_SERVICE->op.ETASK_run(ETASK))
#define sys_event_task_stop(ETASK)	(SYS_SERVICE->op.ETASK_stop(ETASK))

/* Default string if optional NAME (NM) string is omitted will contain the source FILE:LINE */

/* POLL_ENTRY = */
#define sys_poll_enable(ETASK, FN, ENV, FD, EVENTS, NM...) \
	    _sys_poll_enable((ETASK), (FN), (ENV), (FD), (EVENTS), ##NM, FL_STR)
#define _sys_poll_enable(ETASK, FN, ENV, FD, EVENTS, NM, JUNK...) \
	    (SYS_SERVICE->op.ETASK_poll_enable((ETASK), (FN), (ENV), (FD), (EVENTS), (NM)))

#define sys_poll_disable(ETASK, POLL_ENTRY) \
	    (SYS_SERVICE->op.ETASK_poll_disable_sync((ETASK), (POLL_ENTRY)))

/* ALARM = */
#define sys_alarm_set(ETASK, FN, ENV, EXPIRE, NM...) \
	    _sys_alarm_set((ETASK), (FN), (ENV), (EXPIRE), ##NM, FL_STR)
#define _sys_alarm_set(ETASK, FN, ENV, EXPIRE, NM, JUNK...) \
	    (SYS_SERVICE->op.ETASK_alarm_set((ETASK), (FN), (ENV), (EXPIRE), (NM)))

#define sys_alarm_cancel(ETASK, ALARM)	(SYS_SERVICE->op.ETASK_alarm_cancel_sync((ETASK), (ALARM)))

/* CB = */
#define sys_callback_schedule(ETASK, FN, ENV, ARG, ERR, NM...) \
	    _sys_callback_schedule((ETASK), (FN), (ENV), (ARG), (ERR), ##NM, FL_STR)
#define _sys_callback_schedule(ETASK, FN, ENV, ARG, ERR, NM, JUNK...) \
	    (SYS_SERVICE->op.ETASK_callback_schedule((ETASK), (FN), (ENV), (ARG), (ERR), (NM)))

#define sys_callback_cancel(ETASK, CB) \
	    (SYS_SERVICE->op.ETASK_callback_cancel_sync((ETASK), (CB)))

/* lopri_CB = */
#define sys_callback_schedule_lopri(ETASK, FN, ENV, ARG, ERR, NM...) \
	    _sys_callback_schedule_lopri((ETASK), (FN), (ENV), (ARG), (ERR), ##NM, FL_STR)
#define _sys_callback_schedule_lopri(ETASK, FN, ENV, ARG, ERR, NM, JUNK...) \
	    (SYS_SERVICE->op.ETASK_callback_schedule_lopri((ETASK), (FN), (ENV), (ARG), (ERR), (NM)))

#define sys_callback_cancel_lopri(ETASK, CB) \
	    (SYS_SERVICE->op.ETASK_callback_cancel_lopri_sync((ETASK), (CB))

/* Some reasonable defaults that may be used in sys_event_task_cfg */
#define SYS_ETASK_MAX_STEPS 100
#define SYS_ETASK_MAX_POLLS 32

#define SYS_SOCKET_XMIT	    ( EPOLLOUT | EPOLLHUP | EPOLLERR			    )
#define SYS_SOCKET_XMIT_ET  ( EPOLLOUT | EPOLLHUP | EPOLLERR              | EPOLLET )
#define SYS_SOCKET_RECV_ET  ( EPOLLIN  | EPOLLHUP | EPOLLERR | EPOLLRDHUP | EPOLLET )
#define SYS_SOCKET_RECV	    ( EPOLLIN  | EPOLLHUP | EPOLLERR | EPOLLRDHUP           )
#define SYS_SOCKET_ERR      (            EPOLLHUP | EPOLLERR | EPOLLRDHUP           )

/*** sys_threads ***/

//XXX should move to .c file -- treat as opaque
typedef struct sys_thread {
    void		  * run_env;	    /* argument to run_fn */
    error_t		  (*run_fn)(void *);/* thread's work function */
    char *		    name;	    /* owned string */
    pthread_t	            pthread_id;	    /* posix thread_id */
    sys_time_t		    dob;	    /* thread creation time */
    pid_t	            tid;	    /* thread ID */
    int			    nice;	    /* thread initial priority */
    uint32_t		    spare32;
    cpu_set_t		    cpu_mask;	    /* thread initial cpu_mask */
} * sys_thread_t;

#define sys_thread_name(THREAD)	((THREAD) ? (THREAD)->name : "ERROR: NULL THREAD")
#define sys_thread_num(THREAD)	((THREAD) ? (THREAD)->tid : 0)

/* These are provided by the sys_service Implementor */

/* Pointer to current pthread's sys_thread */
#define sys_thread_current()	sys_thread
extern __thread sys_thread_t	sys_thread;

/* Pointer to current pthread's sys_event_task (NULL if not an event thread) */
#define sys_event_task_current()	sys_event_task
extern __thread sys_event_task_t	sys_event_task;

/******************************************************************************/

//XXXX ADD sys_buf_allocator_set() to the sys_services API
extern void _mem_buf_allocator_set(void * buf, const char * caller_id);
#define sys_buf_allocator_set(buf, caller_id) _mem_buf_allocator_set((buf), (caller_id))

//XXXX ADD mte_signal_handler_set() to the sys_services API
extern int mte_signal_handler_set(uint32_t signum, void (*handler)(uint32_t)); //XXXX

#endif /* SYS_SERVICE_H */
