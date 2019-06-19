/* sys_debug.h
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Macro families:
 *	expect -- warning checks done in DEBUG builds only
 *	assert -- fatal checks done in DEBUG builds only
 *	verify -- fatal checks done in all builds
 *
 * Use of  assert_eq(x, y)  rather than  assert(x == y)  allows a failed assertion
 * to print the values of x and y.  Inequality checks:
 *	SIGNED:	    _lt	    _le	    _ge	    _gt		("less", "greater")
 *	UNSIGNED:   _b	    _be,    _ae,    _a		("below", "above")
 *
 */
#ifndef SYS_DEBUG_H
#define SYS_DEBUG_H
#include <signal.h>

#include "sys_service.h"

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

#ifdef NAME
#define LOG_NAME()			__stringify(NAME)
#else
#define LOG_NAME()			__func__
#endif

extern void bp(void);          /* Convenient function to set breakpoint on */
extern void sys_breakpoint(void);

/***** Assertions, etc *****/

#define CONCAT(a, b)			__CONCAT__(a, b)
#define __CONCAT__(a, b)		a##b

/* Compile-time assertion check */
#define assert_static(e) ;enum { CONCAT(static_assert_, __COUNTER__) = 1/(!!(e)) }
assert_static(sizeof(void *) == 8);

/* Avoid "unused variable" warnings from the compiler */
#define __USE(x)    ({ if (0 && (uintptr_t)(x)==0) {}; 0; })

#define _CAST_UP(x)  ((int64_t)(x))
#undef assert

/** "verify" checks are done in all builds, DEBUG and non-DEBUG **/

#define verify_noerr(err, fmtargs...) _verify_noerr(err, ""fmtargs)
#define _verify_noerr(err, fmt, args...)					\
    do {									\
	if (unlikely((err) != E_OK)) {						\
	    sys_panic("syscall error "fmt": errno=%d %s",			\
			##args, err, strerror(err));				\
	}									\
    } while (0)

/* Check a return code from a system or library call that must always succeed */
#define verify_rc(rc, call, fmtargs...) _verify_rc(rc, call, ""fmtargs)
#define _verify_rc(rc, call, fmt, args...)					\
    do {									\
	if (unlikely((rc) < 0)) {						\
	    sys_panic("%s failed: %d '%s' "fmt,					\
	        #call, (int)rc, strerror(rc == -1 ? errno : (int)-rc), ##args); \
	}									\
    } while (0)

/* returns true, or dies if condition is zero */
#define verify(condition, fmtargs...) _verify((condition), #condition, ""fmtargs)
#define _verify(condition, COND_STR, fmt, args...) ({				\
    int64_t const _verify_val = _CAST_UP(condition);				\
    if (unlikely(!_verify_val)) {						\
	sys_panic("ASSERTION FAILED: '%s' -- %s: "fmt,				\
		    COND_STR, FL_STR, ##args);					\
    }										\
    true;									\
})

/* returns true, or dies if value1 does not match value2 */
#define verify_eq(value1, value2, fmtargs...)					\
		    _verify_eq((value1), (value2), #value1, #value2, ""fmtargs)
#define _verify_eq(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    int64_t const _verify_val1 = _CAST_UP(value1);				\
    int64_t const _verify_val2 = _CAST_UP(value2);				\
    if (unlikely(_verify_val1 != _verify_val2)) {				\
	sys_panic("ASSERTION FAILED: '%s' (%"PRId64"/0x%"PRIx64") == "		\
		  "(%"PRId64"/0x%"PRIx64") '%s' -- %s: "fmt,			\
		  VAL_STR, _verify_val1,  _verify_val1, _verify_val2,		\
		  _verify_val2, VAL_STR2, FL_STR, ##args);			\
    }										\
    true;									\
})

#define verify_le(value1, value2, fmtargs...)					\
		    _verify_le((value1), (value2), #value1, #value2, ""fmtargs)
#define _verify_le(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    int64_t const _verify_val1 = _CAST_UP(value1);				\
    int64_t const _verify_val2 = _CAST_UP(value2);				\
    if (unlikely((_verify_val1) > (_verify_val2))) {				\
	sys_panic("ASSERTION FAILED: '%s' (%"PRId64"/0x%"PRIx64") <= (%"PRId64"/0x%"PRIx64 \
		  ") '%s' -- %s: "fmt,						\
		  VAL_STR, _verify_val1,  _verify_val1, _verify_val2,		\
		  _verify_val2, VAL_STR2, FL_STR, ##args);			\
    }										\
    true;									\
})

#define verify_ge(value1, value2, fmtargs...)					\
		    _verify_ge((value1), (value2), #value1, #value2, ""fmtargs)
#define _verify_ge(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    int64_t const _verify_val1 = _CAST_UP(value1);				\
    int64_t const _verify_val2 = _CAST_UP(value2);				\
    if (unlikely((_verify_val1) < (_verify_val2))) {				\
	sys_panic("ASSERTION FAILED: '%s' (%"PRId64"/0x%"PRIx64") >= (%"PRId64"/0x%"PRIx64 \
		  ") '%s' -- %s: "fmt,						\
		  VAL_STR, _verify_val1,  _verify_val1, _verify_val2,		\
		  _verify_val2, VAL_STR2, FL_STR, ##args);			\
    }										\
    true;									\
})

#define verify_be(value1, value2, fmtargs...)					\
		    _verify_be((value1), (value2), #value1, #value2, ""fmtargs)
#define _verify_be(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    uint64_t const _verify_val1 = _CAST_UP(value1);				\
    uint64_t const _verify_val2 = _CAST_UP(value2);				\
    if (unlikely((_verify_val1) > (_verify_val2))) {				\
	sys_panic("ASSERTION FAILED: '%s' (%"PRIu64"/0x%"PRIx64") <= (%"PRIu64"/0x%"PRIx64 \
		  ") '%s' -- %s: "fmt,						\
		  VAL_STR, _verify_val1,  _verify_val1, _verify_val2,		\
		  _verify_val2, VAL_STR2, FL_STR, ##args);			\
    }										\
    true;									\
})

#define verify_ae(value1, value2, fmtargs...)					\
		    _verify_ae((value1), (value2), #value1, #value2, ""fmtargs)
#define _verify_ae(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    uint64_t const _verify_val1 = _CAST_UP(value1);				\
    uint64_t const _verify_val2 = _CAST_UP(value2);				\
    if (unlikely((_verify_val1) < (_verify_val2))) {				\
	sys_panic("ASSERTION FAILED: '%s' (%"PRIu64"/0x%"PRIx64") >= (%"PRIu64"/0x%"PRIx64 \
		  ") '%s' -- %s: "fmt,						\
		  VAL_STR, _verify_val1,  _verify_val1, _verify_val2,		\
		  _verify_val2, VAL_STR2, FL_STR, ##args);			\
    }										\
    true;									\
})

/* returns true, or dies if b is not a boolean value (true or false) */
#define verify_is_bool(b, fmtargs...) _verify_is_bool((b), #b, ""fmtargs)
#define _verify_is_bool(b, B_STR, fmt, args...) ({				\
    int64_t const bb = (b);							\
    if (unlikely(!(bb == true || bb == false))) {				\
	sys_panic("ASSERTION FAILED: assert_is_bool(%s) = %"PRId64" = 0x%"PRIx64\
		  " -- %s: "fmt, B_STR, bb, bb, FL_STR, ##args);		\
    }										\
    true;									\
})

/* returns true if b1 and b2 are equal and boolean, else dies */
#define verify_eq_bool(b1, b2, fmtargs...) _verify_eq_bool((b1), (b2), #b1, #b2, ""fmtargs)
#define _verify_eq_bool(b1, b2, B1_STR, B2_STR, fmt, args...) ({		\
    int64_t const bb1 = (b1);							\
    int64_t const bb2 = (b2);							\
    _verify_is_bool(bb1, B1_STR, fmt, ##args);					\
    _verify_is_bool(bb2, B2_STR, fmt, ##args);					\
    _verify_eq(bb1, bb2, B1_STR, B2_STR, fmt, ##args);				\
    true;									\
})

/* returns true, or dies if x is true/nonzero but y is false/zero */
#define verify_imply(x, y, fmtargs...) _verify_imply((x), (y), #x, #y, ""fmtargs)
#define _verify_imply(x, y, X_STR, Y_STR, fmt, args...) ({			\
    int64_t const xx = _CAST_UP(x);						\
    if (xx) {									\
	int64_t const yy = _CAST_UP(y);						\
	if (unlikely(!yy)) {							\
	    sys_panic("ASSERTION FAILED: (%s %"PRId64"/0x%"PRIx64") --> "	\
		      "(%"PRId64"/0x%"PRIx64" %s) -- %s: "fmt,			\
		      X_STR, xx, xx, yy, yy, Y_STR, FL_STR, ##args);		\
	}									\
    }										\
    true;									\
})

/** "assertion" checks are done in DEBUG builds only **/

#if defined(DEBUG) && DEBUG

#define assert(condition, fmtargs...) 	    _verify((condition), #condition, ""fmtargs) 
#define assert_eq(x, y, fmtargs...) 	    _verify_eq((x), (y), #x, #y, ""fmtargs)
#define assert_le(x, y, fmtargs...) 	    _verify_le((x), (y), #x, #y, ""fmtargs)
#define assert_ge(x, y, fmtargs...) 	    _verify_ge((x), (y), #x, #y, ""fmtargs)
#define assert_be(x, y, fmtargs...) 	    _verify_be((x), (y), #x, #y, ""fmtargs)
#define assert_ae(x, y, fmtargs...) 	    _verify_ae((x), (y), #x, #y, ""fmtargs)
#define assert_is_bool(b, fmtargs...) 	    _verify_is_bool((b), #b, ""fmtargs)
#define assert_eq_bool(b1, b2, fmtargs...)  _verify_eq_bool((b1), (b2), #b1, #b2, ""fmtargs)
#define assert_imply(x, y, fmtargs...) 	    _verify_imply((x), (y), #x, #y, ""fmtargs)

#else /* !DEBUG */

#define assert(condition, fmtargs...)	    (void)(__USE(condition))
#define assert_eq(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define assert_le(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define assert_ge(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define assert_be(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define assert_ae(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define assert_is_bool(b, fmtargs...)	    (void)(__USE(b))
#define assert_eq_bool(b1, b2, fmtargs...)  (void)(__USE(b1) && __USE(b2))
#define assert_imply(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))

#endif /* !DEBUG */

/* Expects (err == 0) -- works on kernel-style errnos and userland-style errnos */
#define expect_noerr(err, fmtargs...) _expect_noerr(err, ""fmtargs)
#define _expect_noerr(err, fmt, args...)					\
    do {									\
	if (unlikely((err) != E_OK)) {						\
	    sys_warning("syscall error "fmt": errno=%d %s",			\
			##args, (int)err, strerror(err>0?err:-err));		\
	}									\
    } while (0)

/* Expects (rc >= 0) -- works on kernel-style errnos and userland-style errnos */
#define expect_rc(rc, call, fmtargs...) _expect_rc(rc, call, ""fmtargs)
#define _expect_rc(rc, call, fmt, args...)					\
    do {									\
	if (unlikely((rc) < 0)) {						\
	    sys_warning("%s syscall: rc=%d err=%d %s "fmt,			\
		        #call, (int)rc, rc == -1 ? errno : (int)-rc,		\
			  strerror(rc == -1 ? errno : (int)-rc), ##args);	\
	}									\
    } while (0)

/** Below "expect" checks are done in DEBUG builds only **/
#if defined(DEBUG) && DEBUG

/* returns true, or warns if condition is zero */
#define expect(condition, fmtargs...) _expect((condition), #condition, ""fmtargs)
#define _expect(condition, COND_STR, fmt, args...) ({				\
    int64_t const _expect_val = _CAST_UP(condition);				\
    if (unlikely(!_expect_val)) {						\
	sys_warning("EXPECTATION UNMET: '%s' -- %s: "fmt, COND_STR,		\
		 FL_STR, ##args);						\
	sys_backtrace("failure of expectation");				\
	sys_breakpoint();							\
    }										\
    true;									\
})

/* returns true, or warns if value1 does not match value2 */
#define expect_eq(value1, value2, fmtargs...)					\
		    _expect_eq((value1), (value2), #value1, #value2, ""fmtargs)
#define _expect_eq(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    int64_t const _expect_val1 = _CAST_UP(value1);				\
    int64_t const _expect_val2 = _CAST_UP(value2);				\
    if (unlikely(_expect_val1 != _expect_val2)) {				\
	sys_warning("EXPECTATION UNMET: '%s' (%"PRId64") == (%"PRId64") '%s'"	\
		 " -- %s: "fmt, VAL_STR, _expect_val1, _expect_val2,		\
		 VAL_STR2, FL_STR, ##args);					\
	sys_backtrace("failure of expectation");				\
	sys_breakpoint();							\
    }										\
    true;									\
})

/* returns true, or warns if value1 does not match value2 */
#define expect_le(value1, value2, fmtargs...)					\
		    _expect_le((value1), (value2), #value1, #value2, ""fmtargs)
#define _expect_le(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    int64_t const _expect_val1 = _CAST_UP(value1);				\
    int64_t const _expect_val2 = _CAST_UP(value2);				\
    if (unlikely((_expect_val1) > (_expect_val2))) {				\
	sys_warning("EXPECTATION UNMET: '%s' (%"PRId64") <= (%"PRId64") '%s'"	\
		 " -- %s: "fmt, VAL_STR, _expect_val1, _expect_val2,		\
		 VAL_STR2, FL_STR, ##args);					\
	sys_backtrace("failure of expectation");				\
	sys_breakpoint();							\
    }										\
    true;									\
})

/* returns true, or warns if value1 does not match value2 */
#define expect_ge(value1, value2, fmtargs...)					\
		    _expect_ge((value1), (value2), #value1, #value2, ""fmtargs)
#define _expect_ge(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    int64_t const _expect_val1 = _CAST_UP(value1);				\
    int64_t const _expect_val2 = _CAST_UP(value2);				\
    if (unlikely((_expect_val1) < (_expect_val2))) {				\
	sys_warning("EXPECTATION UNMET: '%s' (%"PRId64") >= (%"PRId64") '%s'"	\
		 " -- %s: "fmt, VAL_STR, _expect_val1, _expect_val2,		\
		 VAL_STR2, FL_STR, ##args);					\
	sys_backtrace("failure of expectation");				\
	sys_breakpoint();							\
    }										\
    true;									\
})

/* returns true, or warns if value1 does not match value2 */
#define expect_be(value1, value2, fmtargs...)					\
		    _expect_be((value1), (value2), #value1, #value2, ""fmtargs)
#define _expect_be(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    uint64_t const _expect_val1 = _CAST_UP(value1);				\
    uint64_t const _expect_val2 = _CAST_UP(value2);				\
    if (unlikely((_expect_val1) > (_expect_val2))) {				\
	sys_warning("EXPECTATION UNMET: '%s' (%"PRId64") <= (%"PRId64") '%s'"	\
		 " -- %s: "fmt, VAL_STR, _expect_val1, _expect_val2,		\
		 VAL_STR2, FL_STR, ##args);					\
	sys_backtrace("failure of expectation");				\
	sys_breakpoint();							\
    }										\
    true;									\
})

/* returns true, or warns if value1 does not match value2 */
#define expect_ae(value1, value2, fmtargs...)					\
		    _expect_ae((value1), (value2), #value1, #value2, ""fmtargs)
#define _expect_ae(value1, value2, VAL_STR, VAL_STR2, fmt, args...) ({		\
    uint64_t const _expect_val1 = _CAST_UP(value1);				\
    uint64_t const _expect_val2 = _CAST_UP(value2);				\
    if (unlikely((_expect_val1) < (_expect_val2))) {				\
	sys_warning("EXPECTATION UNMET: '%s' (%"PRId64") >= (%"PRId64") '%s'"	\
		 " -- %s: "fmt, VAL_STR, _expect_val1, _expect_val2,		\
		 VAL_STR2, FL_STR, ##args);					\
	sys_backtrace("failure of expectation");				\
	sys_breakpoint();							\
    }										\
    true;									\
})

/* returns true, or warns unless b1 and b2 are equal and boolean */
#define expect_eq_bool(b1, b2, fmtargs...) _expect_eq_bool((b1), (b2), #b1, #b2, ""fmtargs)
#define _expect_eq_bool(b1, b2, B1_STR, B2_STR, fmt, args...) ({		\
    int64_t const bb1 = (b1);							\
    int64_t const bb2 = (b2);							\
    _verify_is_bool(bb1, B1_STR, fmt, ##args);					\
    _verify_is_bool(bb2, B2_STR, fmt, ##args);					\
    _expect_eq(bb1, bb2, B1_STR, B2_STR, fmt, ##args);				\
    true;									\
})

/* returns true, or warns if x is true/nonzero but y is false/zero */
#define expect_imply(x, y, fmtargs...) _expect_imply((x), (y), #x, #y, ""fmtargs)
#define _expect_imply(x, y, X_STR, Y_STR, fmt, args...) ({			\
    int64_t const xx = _CAST_UP(x);						\
    if (xx) {									\
	int64_t const yy = _CAST_UP(y);						\
	if (unlikely(!yy)) {							\
	    sys_warning("EXPECTATION UNMET: (%s %"PRId64") --> (%"PRId64" %s)"	\
		     " -- %s: "fmt, X_STR, xx, yy, Y_STR, FL_STR, ##args);	\
	sys_backtrace("failure of expectation");				\
	sys_breakpoint();							\
	}									\
    }										\
    true;									\
})

#else /* !DEBUG */

#define expect(condition, fmtargs...)	    (void)(__USE(condition))
#define expect_eq(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define expect_le(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define expect_ge(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define expect_ae(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define expect_be(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))
#define expect_eq_bool(b1, b2, fmtargs...)  (void)(__USE(b1) && __USE(b2))
#define expect_imply(x, y, fmtargs...)	    (void)(__USE(x) && __USE(y))

#endif

#define verify_lt(x, y, fmtargs...)	    verify_le((x)+1, (y), fmtargs)
#define verify_gt(x, y, fmtargs...)	    verify_ge((x)-1, (y), fmtargs)
#define expect_lt(x, y, fmtargs...)	    expect_le((x)+1, (y), fmtargs)
#define expect_gt(x, y, fmtargs...)	    expect_ge((x)-1, (y), fmtargs)
#define assert_lt(x, y, fmtargs...)	    assert_le((x)+1, (y), fmtargs)
#define assert_gt(x, y, fmtargs...)	    assert_ge((x)-1, (y), fmtargs)

#define verify_b(x, y, fmtargs...)	    verify_be((x)+1, (y), fmtargs)
#define verify_a(x, y, fmtargs...)	    verify_ae((x)-1, (y), fmtargs)
#define expect_b(x, y, fmtargs...)	    expect_be((x)+1, (y), fmtargs)
#define expect_a(x, y, fmtargs...)	    expect_ae((x)-1, (y), fmtargs)
#define assert_b(x, y, fmtargs...)	    assert_be((x)+1, (y), fmtargs)
#define assert_a(x, y, fmtargs...)	    assert_ae((x)-1, (y), fmtargs)

/***** String formatting and output *****/

/* Format result strings longer than this are less efficient */
#define SYS_SPRINTF_MAX_TYPICAL (8*1024)    /* default bytes of stack buffer allocated */
#define SYS_SPRINTF_MAX_PLAUSIBLE (256*1024)/* max output string size for second try */

/* Return a newly-allocated freeable formatted string from the printf-like arguments */
//XXX These should be non-inline varargs functions (instead of macros)
#define _MIN_(a,b) (((a)<(b))?(a):(b))
#define sys_sprintf(fmt, args...)						\
	    ({									\
		char * _ret;                                                    \
		char _ss_tmp[SYS_SPRINTF_MAX_TYPICAL];				\
		int const _rc = snprintf(_ss_tmp, sizeof(_ss_tmp), fmt, ##args);\
		if (_rc < (int)sizeof(_ss_tmp)) {                               \
		    assert_eq(_rc, strlen(_ss_tmp));				\
		    _ret = sys_mem_dup(_ss_tmp, 1 + _rc);			\
		} else {                                                        \
		    char _ss_tmp2[_MIN_(1 + _rc, SYS_SPRINTF_MAX_PLAUSIBLE)];	\
		    int const _rc2 = snprintf(_ss_tmp2, 1 + _rc, fmt, ##args);	\
		    assert_eq(_rc2, strlen(_ss_tmp2));				\
		    assert_eq(_rc2, _rc);					\
		    _ret = sys_mem_dup(_ss_tmp2, 1 + _rc);			\
		}                                                               \
		_ret;                                                           \
	    })

#define sys_vsprintf(fmt, va)							\
	    ({									\
		char * _ret;                                                    \
		char _ss_tmp[SYS_SPRINTF_MAX_TYPICAL];				\
		int const _rc = vsnprintf(_ss_tmp, sizeof(_ss_tmp), fmt, va);   \
		if (_rc < (int)sizeof(_ss_tmp)) {                               \
		    _ret = sys_mem_dup(_ss_tmp, 1 + _rc);			\
		} else {                                                        \
		    /* XXX FIX sys_vsprintf truncated output string */		\
		    _ret = sys_mem_dup(_ss_tmp, sizeof(_ss_tmp));		\
		}                                                               \
		_ret;                                                           \
	    })

/* Append a formatted string to an existing prefix string -- prefix may be NULL --
 * the prefix string is consumed and a pointer to the result string is returned */
//XXXX TUNE optimize sys_sprintf_append
#define sys_sprintf_append(str, fmt, args...) ({				\
	    string_t nstr = sys_sprintf("%s"fmt, (str) ? : "", ##args);		\
	    if (str) string_free(str);						\
	    nstr; })

#define sys_sprintf_append_nl(prefix, fmt, args...)				\
    string_concat_free((prefix), sys_sprintf(fmt"\n", ##args))

/* Print to stderr or the specified file, without added prefix or newline */
//XXXX Use unlocked_stdio in place of fprintf if aborting
#define sys_fprintf(file, fmt, args...)	(fprintf((file), fmt, ##args), fflush(file))
#define sys_eprint_str_plain(str)	sys_fprintf(stderr, "%s", str)

/* Generate an output line prefix string with timestamp and tid into buf */
/* This function is provided by the sys_service Implementor */
extern uint32_t sys_eprint_prefix_str(char * const buf, uint32_t const buflen);

/* Print to stderr with timestamp/tid prefix */
#define sys_eprintf(fmt, args...) do {						\
    char _se_buf[64];								\
    sys_eprint_prefix_str(_se_buf, sizeof(_se_buf));				\
    sys_fprintf(stderr, "E>%s: "fmt, _se_buf, ##args);				\
} while (0)

#define sys_veprintf(fmt, va)		vfprintf(stderr, fmt, va)

/***** Selectable logging *****/

static int _trace_enabled = TRACE_TRACE;		/* build defaults */
static int _trace_enabled_verbose = TRACE_VERBOSE;
extern int sys_trace_enabled_syscall;

#define trace_tooverbose(fmtargs...)	do { } while (0)
#define trace_verbose(fmtargs...)	_trace_verbose(LOG_NAME(), ""fmtargs)
#define trace(fmtargs...)		_trace(LOG_NAME(), ""fmtargs)
#define trace_always(fmtargs...)	_trace_uncond(LOG_NAME(), ""fmtargs)

#define sys_error(fmtargs...)		_trace_uncond(LOG_NAME(), "ERROR: "fmtargs)
#define sys_warning(fmtargs...)		_trace_uncond(LOG_NAME(), "WARNING: "fmtargs)
#define sys_notice(fmtargs...)		_trace_uncond(LOG_NAME(), "NOTICE: "fmtargs)

#define trace_init(_on_off_trace, _on_off_verbose)				\
	    do {								\
		_trace_enabled = (_on_off_trace);				\
		_trace_enabled_verbose = (_on_off_verbose);			\
	    } while (0)

static inline void trace_enable(int const _flag)	 { _trace_enabled         = _flag; }
static inline void trace_enable_verbose(int const _flag) { _trace_enabled_verbose = _flag; }

#define trace_is_enabled()		_trace_enabled
#define trace_verbose_is_enabled()	_trace_enabled_verbose

#define _trace_uncond(_name, _fmt, _args...)					\
	    do {								\
		sys_eprintf("%s:%s:%u: "_fmt"\n",				\
		    _name, __func__, __LINE__, ##_args);			\
	    } while (0)

#define _trace(_name, _fmt, _args...)						\
	    do {								\
		if (trace_is_enabled()) {					\
		    sys_eprintf("%s:%s:%u: "_fmt"\n",				\
			_name, __func__, __LINE__, ##_args);			\
		}								\
	    } while (0)

#if !OPTIMIZED
  #define _trace_verbose(_name, _fmt, _args...)					\
	    do {								\
		if (trace_verbose_is_enabled()) {				\
		    sys_eprintf("%s:%s:%u: "_fmt"\n",				\
			_name, __func__, __LINE__, ##_args);			\
		}								\
	    } while (0)
#else
    #define _trace_verbose(_name, _fmt, _args...) do { } while (0)
#endif

#define trace_syscall(call, ret, err, fmtargs...)   _trace_syscall_(call, (ret), (err), ""fmtargs)
#define _trace_syscall_(call, ret, err, fmt, args...)				\
					    _trace_syscall(call, (ret), (err), fmt, ##args)
#define _trace_syscall(_call, _ret, _err, _fmt, _args...)			\
    do {			    \
	if (_trace_enabled || sys_trace_enabled_syscall) {			\
	    sys_eprintf("SYSCALL "_call"(ret=%d err=%d) "_fmt"\n", (_ret), (int)(_err), ##_args); \
	}									\
    } while (0)

/***** Symbols and Dumps *****/

/* Walk up the stack generating a snapshot of the calling chain */
extern uint32_t sys_backtrace_get_max(void * bt[], uint32_t const stackframes_max);

/* Format a previously-taken backtrace snapshot into an engineer-readable string */
extern sstring_t sys_backtrace_fmt(void * bt[], uint32_t const nframes);

/* Format and dump a previously-taken backtrace snapshot */
extern void sys_backtrace_dump(void * bt[], uint32_t const nframes);

/* Dump out a signal frame (called from signal handlers) */
extern void sys_signal_dump(int const signum, siginfo_t * const siginfo, ucontext_t * const ucontext,
								sstring_t const whence);

/* Dump to stderr a memory range covering the addresses [start, end) */
extern void mem_dump(uintptr_t const start, uintptr_t const end, sstring_t const reason);
extern void mem_dump_stack(uintptr_t const start, uintptr_t const end, uintptr_t const SP,
				      uintptr_t const BP, sstring_t const reason);

/* Try to get a symbol for the address (with or without stack-relative notations) */
extern sstring_t sys_symbol(uintptr_t const addr);
extern sstring_t sys_symbol_stack_ref(uintptr_t const addr, uintptr_t const SP, uintptr_t const BP);

/***** Panics *****/

/* Abort the process with a message to the error logging stream */
#define sys_panic(fmtargs...)		_sys_panic(""fmtargs)
#define _sys_panic(fmt, args...) \
	    ({ \
	        sys_eprint_str_plain("\n\n"); \
		sys_eprintf("PANIC in %s: "fmt"\n", __func__, ##args); \
		sys_abort(); \
	    })

/* Abort the process with a message to the error logging stream describing an errno */
#define sys_panic_err(err, fmtargs...) _sys_panic_err(err, ""fmtargs)
#define _sys_panic_err(err, fmt, args...) \
	    _sys_panic("errno=%u (%s) "fmt, err, strerror(err), ##args)

#endif /* SYS_DEBUG_H */
