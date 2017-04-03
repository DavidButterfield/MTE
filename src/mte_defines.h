/* mte_defines.h
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
*/
#ifndef MTE_DEFINES_H
#define MTE_DEFINES_H
#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
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

#ifndef DEBUG
#define DEBUG				false	/* overridden by cc -DDEBUG=1 */
#endif

#ifndef TRACE_TOOVERBOSE
#define TRACE_TOOVERBOSE		false
#endif

#ifndef TRACE_VERBOSE
#define TRACE_VERBOSE			TRACE_TOOVERBOSE
#endif

#ifndef TRACE_TRACE
#define TRACE_TRACE			TRACE_VERBOSE
#endif

#ifndef OPTIMIZED
#define OPTIMIZED                       false
#endif

#define gettid()                        ((pid_t)(syscall(SYS_gettid)))	/* thread-id */
#define tkill(tid, sig)			(syscall(__NR_tkill, tid, sig)) /* thread signal */

#define __stringify(TOKEN)              __STRINGIFY(TOKEN)
#define __STRINGIFY(TOKEN)              #TOKEN

#define FL_STR                          __FILE__":"__stringify(__LINE__)

#ifndef NVALGRIND
  #include "valgrind.h"
  #define valgrind_is_active()          (RUNNING_ON_VALGRIND)
  #define valgrind_backtrace(f, a...)	(VALGRIND_PRINTF_BACKTRACE(f, ##a))
#else
  #define valgrind_is_active()          false
  #define valgrind_backtrace(f, a...)	do { } while (0)
#endif

/* Optimizer hints */
#define always_inline			inline __attribute__((__always_inline__))
#define NORETURN			__attribute__((__noreturn__))
#define ALIGNED(align)			__attribute__((aligned(align)))
#define IS_ALIGNED(ptr, align)		likely((align) && !((uintptr_t)(ptr) % (align)))
#define IS_CONSTANT(expr)		__builtin_constant_p(expr)
#define ASSUME_ALIGNED(v, a)		__builtin_assume_aligned((v), (a))

/* Thread-Local Storage -- one instance per thread */
#define PER_THREAD			__thread

/* Number of elements in a given array */
#define NELEM(array)			(sizeof(array)/sizeof((array)[0]))

/* Offset of a member of a structure */
#define offsetof(TYPE, MEMBER)		__builtin_offsetof(TYPE, MEMBER)

static always_inline void *
unconstify(void const * cvp)
{
    union { void * vp; void const * cvp; } p;
    p.cvp= cvp;
    return p.vp;
}

/* Pointer to the enclosing record of a referenced member, preserving NULL as such */
#define enclosing_record(MEMBERPTR, ENCLOSING_PTRTYPE, MEMBERNAME) \
({  void * const _memberptr = (MEMBERPTR); \
    (_memberptr) \
        ? (ENCLOSING_PTRTYPE) \
	    ((void *)(_memberptr) - (uintptr_t)&((ENCLOSING_PTRTYPE)0)->MEMBERNAME) \
        : (ENCLOSING_PTRTYPE) NULL; \
})

/* Retry system calls after they fail with EINTR */
#define RETRY_EINTR(rc, cmd)		do { (rc) = cmd; } while ((rc) == -1 && errno == EINTR)

typedef int				sys_rc_t;	    /* return code from syscalls */
#define SYS_RC_OK			0

#define false                           (0 == 1)
#define true                            (0 == 0)

typedef const char                    * string_t;           /* owned dynamic string */
typedef const char                    * sstring_t;          /* unowned or static string */

typedef int                             errno_t;            /* errno (or -errno) */
#define E_OK                            0                   /* no error */

typedef uint64_t                        sys_time_t;         /* monotonically-increasing time */
typedef uint64_t                        sys_time_delta_t;   /* time interval in ns */

typedef uint32_t			magic_t;

typedef uint32_t			idx_t;
typedef uint32_t			count_t;
typedef uint32_t			len_t;

typedef uint64_t			lidx_t;
typedef uint64_t			lcount_t;
typedef uint64_t			llen_t;

#define THOUSAND			1000UL
#define MILLION				(THOUSAND * THOUSAND)

#define KILO				1024UL
#define MEGA				(KILO * KILO)

#define TYPE_MAXI(uscalar_type)		((uscalar_type)(-1))
#define VAR_MAXI(uscalar_var)		((typeof(uscalar_var))(-1))

#define DIV(N, D)			(  (typeof(N)) _DIV((N),(D))  )
#define DIV32(N, D)			(  (int32_t) _DIV((N),(D))  )
static inline uint64_t _DIV(uint64_t n, uint64_t d) { return d ? (    n + d/2) / d : 0; }
static inline uint32_t  PCT(uint64_t n, uint64_t d) { return d ? (100*n + d/2) / d : 0; }

/* Compute the minimum or maximum of two UNSIGNED scalar values */
static inline uint64_t MIN(uint64_t const x, uint64_t const y) { return x > y ? y : x; }
static inline uint64_t MAX(uint64_t const x, uint64_t const y) { return x > y ? x : y; }

/* Round UNSIGNED scalar value (v) DOWN or UP to the nearest multiple of quantum (q) */
static inline uint64_t ROUND(    uint64_t const v, uint64_t const q) { return (v + q / 2) / q * q; }
static inline uint64_t ROUNDUP(  uint64_t const v, uint64_t const q) { return (v + q - 1) / q * q; }
static inline uint64_t ROUNDDOWN(uint64_t const v, uint64_t const q) { return (v        ) / q * q; }

#define uint64_log2(v)			((v) ? 63 - __builtin_clzl((uint64_t)(v)) : -1)
#define is_power_of_2(n)		( n && !( n & (n-1) ) )

#define PTR_ALIGN_BITS			3
#define PTR_ALIGN_BYTES			((uint64_t)1 << PTR_ALIGN_BITS)
#define PTR_ALIGNED			ALIGNED(PTR_ALIGN_BYTES)
#define IS_PTR_ALIGNED(p)		IS_ALIGNED((p), PTR_ALIGN_BYTES)

#define CACHE_ALIGN_BITS		6
#define CACHE_ALIGN_BYTES		((uint64_t)1 << CACHE_ALIGN_BITS)
#define CACHE_ALIGNED			ALIGNED(CACHE_ALIGN_BYTES)
#define IS_CACHE_ALIGNED(p)		IS_ALIGNED((p), CACHE_ALIGN_BYTES)

#define SECTOR_ALIGN_BITS		9
#define SECTOR_ALIGN_BYTES		((uint64_t)1 << SECTOR_ALIGN_BITS)
#define SECTOR_ALIGNED			ALIGNED(SECTOR_ALIGN_BYTES)
#define IS_SECTOR_ALIGNED(p)		IS_ALIGNED((p), SECTOR_ALIGN_BYTES)

#define PAGE_ALIGN_BITS			12
#define PAGE_ALIGN_BYTES		((uint64_t)1 << PAGE_ALIGN_BITS)
#define PAGE_ALIGNED			ALIGNED(PAGE_ALIGN_BYTES)
#define IS_PAGE_ALIGNED(p)		IS_ALIGNED((p), PAGE_ALIGN_BYTES)

#if !OPTIMIZED	/* leave thread assertions on even in regular non-DEBUG builds */

#define assert_this_thread_is(thread) \
	    verify_eq((void *)sys_thread, (thread), \
		      "sys_thread='%s' expected='%s'", sys_thread->name, (thread)->name)

#define assert_this_thread_is_not(thread)	\
	     verify(sys_thread != (thread), \
		    "UNEXPECTED: sys_thread='%s' (recursive lock?)", (thread)->name)

#else

#define assert_this_thread_is(thread)	__USE(thread)
#define assert_this_thread_is_not(thread)	__USE(thread)

#endif

#endif /* MTE_DEFINES_H */
