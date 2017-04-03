/* mte_util.h
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 */
#ifndef MTE_UTIL_H
#define MTE_UTIL_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <execinfo.h>
#include <sys/resource.h>

#include "sys_service.h"		/* memory, timers, threads, etc */
#include "sys_debug.h"
#include "mte_defines.h"

/* mte_debug.c */
extern void mte_backtrace(sstring_t const reason);

/* mte_util.c */

void sys_random_seed(uint32_t seed);
uint32_t sys_random(uint64_t mod);

#define sys_time_cal() (time_t)time(NULL)   /* current calendar seconds since 1970 */
string_t sys_time_cal_fmt(time_t const t_cal);
string_t sys_time_fmt_general(sys_time_t t_delta);

int sys_system(string_t cmd);

string_t sys_rusage_fmt(struct rusage * ru_prev);

/* Wrappers for some sys_services */

/* record_alloc / record_free --
 *   Allocate heap space for a structure instance to back the specified pointer -- example:
 *      struct foo * foo_ptr;
 *      foo_ptr = record_alloc(foo_ptr);
 *		    > record_alloc allocates zeroed space for a (struct foo) from the heap;
 *		    > foo_ptr is set to point at the newly-allocated (struct foo);
 *		    > (foo_ptr may be returned to a caller or stored in a state structure).
 *
 *      record_free(foo_ptr);
 *		    > frees the structure pointed to by foo_ptr (modulo refcounting)
 */
#define record_alloc_uninit(ptr_var)	((typeof(ptr_var))sys_mem_alloc(sizeof(*(ptr_var))))
#define record_alloc(ptr_var)		((typeof(ptr_var))sys_mem_zalloc(sizeof(*(ptr_var))))
#define record_free(ptr_var)		sys_mem_free(ptr_var)
#define record_zero(ptr_var)		memset((ptr_var), 0, sizeof(*(ptr_var)))

/* Allocate heap space for an array of items to back the specified pointer */
#define array_alloc(ptr_var, nelem)	((typeof(ptr_var))sys_mem_zalloc((nelem)*sizeof(*(ptr_var))))
#define array_free(ptr_var, nelem)	sys_mem_free((ptr_var), (nelem)*sizeof(*(ptr_var)))
#define array_zero(ptr_var, nelem)	memset((ptr_var), 0, (nelem)*sizeof(*(ptr_var)))

/* Allocate space and make a new copy of the specified sstring (static string, or any string
 * whether or not it was allocated in one of our mem_hdr_t buffers) -- result is a freeable
 * dynamic string
 */
#define sstring_copy(sstr)		sys_mem_dup((sstr), 1+strlen(sstr))

/* Free str unless it is NULL, in which case do nothing */
#define string_free_null(str)		do { if (likely(str != NULL)) string_free(str); } while (0)
#define string_free(str)		sys_mem_free(str)

sys_time_t SYS_TIME_NOW;    /* time as of last inquiry -- only for debugging observability */

/* Using the VDSO page, clock_gettime(CLOCK_MONOTONIC) takes ~50ns @2.4GHz */
#define MTE_time_now() ({							\
    struct timespec _t;								\
    int const _rc_ = clock_gettime(CLOCK_MONOTONIC, &_t);			\
    expect_rc(_rc_, clock_gettime,);						\
    SYS_TIME_NOW = (sys_time_t)(_t.tv_sec*1L*1000*1000*1000 + _t.tv_nsec);	\
})

#define NOW()				MTE_time_now()   /* current "monotonic" time */

/******************************************************************************/

/* Implemented in mte_event_task.c */

extern errno_t		    mte_event_task_init(void);	/* init the mte_event_task.c module */
extern errno_t		    mte_event_task_exit(void);

extern sys_event_task_t	    mte_event_task_alloc(sys_event_task_cfg_t);

extern string_t		    mte_event_task_fmt(sys_event_task_t);
extern errno_t		    mte_event_task_run(sys_event_task_t);
extern errno_t		    mte_event_task_stop(sys_event_task_t);
extern errno_t		    mte_event_task_free(sys_event_task_t);

extern void	            mte_poll_disable_sync(sys_event_task_t, sys_poll_entry_t);

extern sys_poll_entry_t	    mte_poll_enable(sys_event_task_t,
				    void (*fn)(void * env, uintptr_t arg, errno_t), void * env,
				    int fd, unsigned long events, sstring_t name);

extern errno_t		    mte_alarm_cancel_sync(sys_event_task_t, sys_alarm_entry_t);

extern sys_alarm_entry_t    mte_alarm_set(sys_event_task_t,
				    void (*)(void * env, uintptr_t arg, errno_t), void * env,
				    sys_time_t expire, sstring_t name);

extern errno_t		    mte_callback_cancel_sync(sys_event_task_t, sys_sched_entry_t);

extern sys_sched_entry_t    mte_callback_schedule(sys_event_task_t,
				    void (*fn)(void *, uintptr_t, errno_t), void * env,
				    uintptr_t arg, errno_t err, sstring_t name);

extern errno_t		    mte_callback_cancel_lopri_sync(sys_event_task_t, sys_sched_entry_t);

extern sys_sched_entry_t    mte_callback_schedule_lopri(sys_event_task_t,
				    void (*fn)(void *, uintptr_t, errno_t), void * env,
				    uintptr_t arg, errno_t err, sstring_t name);

/******************************************************************************/

extern bool sock_error(int const fd, uint32_t const err, sstring_t const op_str);
extern sys_rc_t sock_getopt(int sock_fd, int level, int optname, void * optvalp, size_t * optlenp);
extern sys_rc_t sock_setopt(int sock_fd, int level, int optname, void const * optvalp, size_t optlen);
extern uint64_t Hz(uint64_t ndelta, sys_time_t tdelta);
extern string_t sys_thread_fmt(sys_thread_t thread);

/* int sock_op(fd, ZRET, OP_NAME, OP_ARGS...)
 *    Returns the result of the operation if the operation was successful.
 *    Returns zero if the event should be ignored (EAGAIN).
 *    Returns -1 on errors indicating the socket should be closed --
 *    ZRET denotes whether (rc == 0) indicates an error (EOF) or success;
 *	   recv functions pass this as -2, xmit as -1, other functions as 0.
 */
#define _sock_op(fd, ZRET, op_str, OP, args...) ({				\
    int _rc;									\
    RETRY_EINTR(_rc, OP(fd, ##args));						\
    errno_t err = errno;							\
    trace_verbose("'%s'", op_str);						\
    _rc > 0 ? _rc : _rc == 0 ? ZRET : sock_error(fd, err, op_str) ? -1 : 0;	\
})

#define sock_op(fd, OP, args...)	_sock_op((fd),  0, #OP"(fd, "#args")", (OP), ##args)
#define sock_op_recv(fd, OP, args...)	_sock_op((fd), -2, #OP"(fd, "#args")", (OP), ##args)
#define sock_op_xmit(fd, OP, args...)	_sock_op((fd), -1, #OP"(fd, "#args")", (OP), ##args)
#define eventfd_op(fd, OP, args...)	_sock_op((fd),  0, #OP"(fd, "#args")", (OP), ##args)

extern string_t sys_tcp_info_get_fmt(int const sock_fd);

/******************************************************************************/

#define this_event_task()   sys_event_task_current()

#define assert_this_event_task_is(event_task) \
	    verify_eq((void *)this_event_task(), (event_task), \
		      "this_event_task='%s' (%u) expected='%s' (%u)", \
		      sys_thread_name(sys_thread_current()), \
		      sys_thread_num(sys_thread_current()), \
		      sys_event_task_name(event_task), \
		      sys_event_task_num(event_task))

extern sstring_t sys_event_task_name(sys_event_task_t event_task);
extern uint32_t sys_event_task_num(sys_event_task_t event_task);

#endif /* MTE_UTIL_H */
