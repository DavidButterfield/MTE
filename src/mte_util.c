/* mte_util.c
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Random infrastructure implementation
 */
#define NAME MTE_UTIL
#include "mte_mttypes.h"
#include "mte_util.h"
  
int sys_trace_enabled_syscall = TRACE_TRACE;

static PER_THREAD unsigned short _sys_random_state[3];

void
sys_random_seed(uint32_t seed)
{
    _sys_random_state[0] = seed;
    _sys_random_state[1] = seed >> 16;
    _sys_random_state[2] = 0xdab;
}

/* Return a "random" value from zero to mod-1, up to 31 bits --
 * if mod == 0 the range is from zero to RAND_MAX
 */
uint32_t
sys_random(uint64_t mod)
{
    assert_be(mod, (uint64_t)RAND_MAX + 1);
    if (mod == 0) mod = (uint64_t)RAND_MAX + 1;

    return jrand48(_sys_random_state) % mod;
}

/*****  Strings and formatting  *****/

string_t
sys_time_cal_fmt(time_t const t_cal)
{
    char buf[32];   /* "at least 26 bytes" -- ctime_r(3) */
    sstring_t const str = ctime_r(&t_cal, buf);
    return sstring_copy(str?: "");
}

/* Return a string representation of the specified time delta: adaptive to range, e.g.
 * "23d 17h 4m 12.345s"  or  "2m 3.141592653s"
 */
string_t
sys_time_fmt_general(sys_time_t t_delta)
{
    uint32_t const t_d =  t_delta / sys_time_delta_of_day(1);  t_delta -= sys_time_delta_of_day(t_d);
    uint32_t const t_h =  t_delta / sys_time_delta_of_hour(1); t_delta -= sys_time_delta_of_hour(t_h);
    uint32_t const t_m =  t_delta / sys_time_delta_of_min(1);  t_delta -= sys_time_delta_of_min(t_m);
    uint32_t const t_s =  t_delta / sys_time_delta_of_sec(1);  t_delta -= sys_time_delta_of_sec(t_s);
    uint32_t const t_ms = t_delta / sys_time_delta_of_ms(1);   t_delta -= sys_time_delta_of_ms(t_ms);
    uint32_t const t_us = t_delta / sys_time_delta_of_us(1);   t_delta -= sys_time_delta_of_us(t_us);
    uint32_t const t_ns = t_delta / sys_time_delta_of_ns(1);   t_delta -= sys_time_delta_of_ns(t_ns);
    expect_eq(t_delta, 0);

    char buf[256];
    count_t count = 0;

    if (t_d) {
	count += snprintf(buf+count, sizeof(buf)-count, "%ud", t_d);
    }
    if (t_d || t_h) {
	count += snprintf(buf+count, sizeof(buf)-count, "%02uh", t_h);
    }
    if (t_d || t_h || t_m) {
       	count += snprintf(buf+count, sizeof(buf)-count, "%02um", t_m);
    }
    if (t_h || t_d) {
	count += snprintf(buf+count, sizeof(buf)-count, "%02us", t_s);
    } else if (t_m) {
	count += snprintf(buf+count, sizeof(buf)-count, "%02u.%03us", t_s, t_ms);
    } else if (t_s || t_ms >= 100) {
	count += snprintf(buf+count, sizeof(buf)-count, "%u.%03u%03us", t_s, t_ms, t_us);
    } else {
	count += snprintf(buf+count, sizeof(buf)-count, "0.%03u%03u%03us", t_ms, t_us, t_ns);
    }

    return sstring_copy(buf);
}

/* Execute a shell command (synchronously) */
int
sys_system(string_t cmd)
{
    fflush(stdout);
    fflush(stderr);

    /* Want to see the command-line *ahead* of the output */
    if (!strstr(cmd, "addr2line")) {
	trace_syscall("system", 0, 0, "%s", cmd);
    }

    int const rc = system(cmd);
    expect_noerr(rc, "system(\"%s\")", cmd);

    return rc;
}

/*****  Resource usage  *****/

#include <sys/resource.h>

/* Format a string describing the rusage since the previous snapshot, and update snapshot */
string_t
sys_rusage_fmt(struct rusage * ru_prev)
{
    /* Fetch the thread's current resource usage stats */
    struct rusage ru;
    int rc = getrusage(RUSAGE_THREAD, &ru);
    verify_rc(rc, getrusage);

    struct rusage ru_zero;
    record_zero(&ru_zero);
    if (ru_prev == NULL) {
	ru_prev = &ru_zero;	    /* no snapshot given; assume thread start */
    }

    uint64_t const usec_u = MILLION * ru.ru_utime.tv_sec + ru.ru_utime.tv_usec;
    uint64_t const usec_s = MILLION * ru.ru_stime.tv_sec + ru.ru_stime.tv_usec;
    uint64_t const prev_u = MILLION * ru_prev->ru_utime.tv_sec + ru_prev->ru_utime.tv_usec;
    uint64_t const prev_s = MILLION * ru_prev->ru_stime.tv_sec + ru_prev->ru_stime.tv_usec;
    uint64_t const delta_u = usec_u - prev_u;
    uint64_t const delta_s = usec_s - prev_s;

#if !TRACE_TOOVERBOSE
    string_t const ret = sys_sprintf("utime=%-8"PRIu64" stime=%-8"PRIu64, delta_u, delta_s);
#else
    uint64_t const delta_ctxsw_vol = ru.ru_nvcsw - ru_prev->ru_nvcsw;
    uint64_t const delta_ctxsw_invol = ru.ru_nivcsw - ru_prev->ru_nivcsw;
    string_t const ret = sys_sprintf(
	    "utime=%-8"PRIu64" stime=%-8"PRIu64" ctxsw_vol=%-6"PRIu64" ctxsw_invol=%-6"PRIu64,
	    delta_u, delta_s, delta_ctxsw_vol, delta_ctxsw_invol);
#endif

    /* Reset the prev stats for next measurement */
    rc = getrusage(RUSAGE_THREAD, &ru);
    verify_rc(rc, getrusage);
    *ru_prev = ru;

    return ret;
}

/*****  MT fifo non-inline functions  *****/

/* Transfer all but (max_leave) members from fifo_src to fifo_dst --
 * returns the number of items transferred
 */
count_t
sys_fifo_xfer_leave(sys_fifo_t * const fifo_dst,
		    sys_fifo_t * const fifo_src, count_t const max_leave)
{
    assert_ae(max_leave, 1);	/* otherwise just call (cheaper) sys_fifo_xfer */

    if (fifo_src->nitem <= max_leave) return 0; /* source fifo too depleted -- nothing to do */

    sys_link_t * f = NULL;	/* the first item we will transfer from src to dst */
    sys_link_t * l = NULL;	/* the last item we will transfer from src to dst */
    count_t nitems_xfer = 0;	/* the number of items we will transfer from src to dst */

    //XXX should count down the "smaller half"
    sys_spin_lock(&fifo_src->lock);
    {
	/* Verify the condition under lock */
	if (fifo_src->nitem > max_leave) {
	    /* fifo_src has excess items beyond what we will leave behind */
	    nitems_xfer = fifo_src->nitem - max_leave;
	    f = fifo_src->head.next;	/* we'll take our share starting with first */
	    /* count down the fifo list to find the last item we want to take */
	    count_t i;				//XXX PERF loop down fifo chain
	    for (i = 1, l = f; i < nitems_xfer; i++, l = l->next) {
		assert(l);
		assert(l != fifo_src->tail.next);
	    }
	    fifo_src->head.next = l->next;
	    l->next = NULL;
	    fifo_src->nitem -= nitems_xfer;
	}
    }
    sys_spin_unlock(&fifo_src->lock);

    if (nitems_xfer) {
	/* Append to fifo_dst the items we took from fifo_src */
	_sys_fifo_append_chain(fifo_dst, f, l, nitems_xfer);
    }

    return nitems_xfer;
}

/* Transfer up to (max_xfer) members from fifo_src to fifo_dst --
 * returns the number of items transferred
 */
count_t
sys_fifo_xfer_max(sys_fifo_t * const fifo_dst,
		  sys_fifo_t * const fifo_src, count_t const max_xfer)
{
    expect_ae(max_xfer, 1);	/* would be kinda lame to call here with max_xfer == 0 */
    if (fifo_src->nitem == 0) return 0;	    /* source fifo empty */

    sys_link_t * f;
    sys_link_t * l;
    count_t nitems_xfer;

    /* Take up to max_xfer items from fifo_src */
    sys_spin_lock(&fifo_src->lock);
    {
	if (fifo_src->nitem > max_xfer) {	/* fifo_src has more than the max we want */
	    nitems_xfer = max_xfer;
	    f = fifo_src->head.next;
	    /* count down the fifo list to find the last item we want to take */
	    count_t i;				//XXX PERF loop down fifo chain
	    for (i = 1, l = f; i < nitems_xfer; i++, l = l->next) {
		assert(l);
		assert(l != fifo_src->tail.next);
	    }
	    fifo_src->head.next = l->next;
	    l->next = NULL;
	    fifo_src->nitem -= nitems_xfer;
	}
	else if (fifo_src->nitem > 0) {		/* we will take all of fifo_src */
	    nitems_xfer = fifo_src->nitem;
	    f = fifo_src->head.next;
	    l = fifo_src->tail.next;
	    /* our convention here is that a fifo's pointers are only good when nitem != 0 */
	    fifo_src->nitem = 0;		/* set the src fifo to empty */
	}
	else {		    /* src fifo was empty (now that we're looking while under lock) */
	    nitems_xfer = 0;
	    l = f = NULL;   /* please the compiler */
	}
    }
    sys_spin_unlock(&fifo_src->lock);

    if (nitems_xfer) {
	_sys_fifo_append_chain(fifo_dst, f, l, nitems_xfer);
    }

    return nitems_xfer;
}

/* Analyze a socket error -- return true to close socket, false to retry later --
 * Bugs in the program panic.
 */
bool
sock_error(int const fd, uint32_t const err, sstring_t const op_str)
{
    switch (err) {

    /* Ignore these events */
#if EAGAIN != EWOULDBLOCK
    case EWOULDBLOCK:		/* Operation would block */
#endif
    case EAGAIN:		/* Try again */
    case EINPROGRESS:		/* Operation now in progress */
	trace_verbose("IGNORE '%s'", op_str);
	return false;		/* Tell our caller to ignore the error */

    /* remote service problem */
    case ECONNREFUSED:		/* Connection refused */
	sys_error("SOCK:%u:NO LISTENER AT DESTINATION -- '%s')", fd, op_str);
	return true;		/* Tell our caller the socket should be closed */

    /* Communication errors */
    case EPIPE:		 	/* Broken pipe */
    case ENONET:	 	/* Machine is not on the network */
    case ENOLINK:	 	/* Link has been severed */
    case ECOMM:		 	/* Communication error on send */
    case EPROTO:	 	/* Protocol error */
    case ESTRPIPE:	 	/* Streams pipe error */
    case ENETDOWN:		/* Network is down */
    case ENETUNREACH:		/* Network is unreachable */
    case ENETRESET:		/* Network dropped connection because of reset */
    case ENOTCONN:		/* Transport endpoint is not connected (any longer) */
    case ECONNABORTED:		/* Software caused connection abort */
    case ECONNRESET:		/* Connection reset by peer */
    case ETIMEDOUT:		/* Connection timed out */
    case EHOSTDOWN:		/* Host is down */
    case EHOSTUNREACH:		/* No route to host */
    {
	sys_error("sock_fd=%u COMMUNICATION ERROR -- '%s' errno=%u '%s'",
		    fd, op_str, err, strerror(err));
	return true;		/* Tell our caller the socket should be closed */
    }

    /* Resource exhaustion -- probably a program memory leak */
    //XXX Instead of panicking, could return an error to the caller for these cases
    case ENOMEM:		/* Out of memory */
    case ENOSR:			/* Out of streams resources */
    case ENOBUFS:		/* No buffer space available */
	sys_error("sock_fd=%u RESOURCE ERROR -- '%s' errno=%u '%s'",
		    fd, op_str, err, strerror(err));
	sys_panic_err(err, "RESOURCE EXHAUSTION: SOCKET: '%s'", op_str);

    /* Configuration errors -- possibly a prior program instance still running */
    //XXX Instead of panicking, could return an error to the caller for these cases
    case EADDRINUSE:		/* Address already in use */
    case EADDRNOTAVAIL:		/* Cannot assign requested address */
	sys_error("sock_d=%u CONFIGURATION ERROR -- '%s' errno=%u '%s'",
		    fd, op_str, err, strerror(err));
	sys_panic_err(err,
	    "CONFIGURATION ERROR or PRIOR SERVER INSTANCE STILL ACTIVE: SOCKET: '%s'", op_str);

    /* All others represent bugs in the program */
    default:
	sys_error("sock_fd=%u PROGRAM ERROR -- '%s' errno=%u '%s'",
		    fd, op_str, err, strerror(err));
	sys_panic_err(err, "PROGRAM ERROR: SOCKET: '%s'", op_str);
    }
}

sys_rc_t
sock_getopt(int const sock_fd, int const level, int const optname,
                                        void * optvalp, size_t * optlenp)
{
    int rc = sock_op(sock_fd, getsockopt, level, optname, optvalp, (socklen_t *)optlenp);
    expect_noerr(rc, "getsockopt(%u, %u, %u, %u, %u)",
                     sock_fd, level, optname, *(int *)optvalp, (int)*optlenp);
    return rc;
}

sys_rc_t
sock_setopt(int const sock_fd, int const level, int const optname,
                                        void const * const optvalp, size_t const optlen)
{
    int rc = sock_op(sock_fd, setsockopt, level, optname, optvalp, optlen);
    expect_noerr(rc, "setsockopt(%u, %u, %u, %u, %u)",
                     sock_fd, level, optname, *(int const *)optvalp, (int)optlen);
    return rc;
}

uint64_t
Hz(uint64_t const ndelta, sys_time_t const tdelta)
{
    if (tdelta == 0) return 0;

    /* Try to avoid 64-bit arithmetic overflow while preserving precision */
    uint64_t scale;
    if      (ndelta < TYPE_MAXI(sys_time_t) / sys_time_delta_of_sec(1))	scale = 1;
    else if (ndelta < TYPE_MAXI(sys_time_t) / sys_time_delta_of_ms(1))	scale = THOUSAND;
    else if (ndelta < TYPE_MAXI(sys_time_t) / sys_time_delta_of_us(1))	scale = MILLION;
    else								scale = THOUSAND * MILLION;

    return sys_time_delta_of_sec(1) / scale * ndelta / tdelta * scale;
}

string_t
sys_thread_fmt(sys_thread_t thread)
{
    return sys_sprintf("name=%s tid=%u pthread_id=0x%"PRIx64", age="SYS_TIME_DELTA_FMT,
		       thread->name, thread->tid, thread->pthread_id,
		       SYS_TIME_DELTA_FIELDS(NOW() - thread->dob));
}

/***** Compile-time option expectation checks *****/

#if TRACE_VERBOSE && !TRACE_TRACE
#warning UNEXPECTED: TRACE_TRACE explicitly disabled but TRACE_VERBOSE explicitly enabled
#endif

#if OPTIMIZED && DEBUG
#warning UNEXPECTED: OPTIMIZED && DEBUG
#endif
