/* mte_service.c
 * Copyright 2016 David A. Butterfield
 * Multithreaded Engine system services Implementor
 */
#define NAME MTE_SERVICE
#include <execinfo.h>
#include <pthread.h>
#include "mtelib.h"

#include "mte_mem.h"	    /* memory and caches */
#include "mte_util.h"

struct sys_service_handle * SYS_SERVICE;

static void *
MEM_alloc(size_t const size, sstring_t whence)
{
    return mem_alloc_uninit_callerid(size, whence);
}

static void *
MEM_zalloc(size_t const size, sstring_t whence)
{
    return mem_alloc_callerid(size, whence);
}

static void *
MEM_realloc(void * const oaddr, size_t const nsize, sstring_t whence)
{
    return mem_realloc_callerid(oaddr, nsize, whence);
}

static void
MEM_free(void const * const addr, sstring_t whence)
{
    mem_drop_callerid(addr, whence);
}

static sys_buf_cache_t
BUF_cache_create(sstring_t name, size_t const size, size_t const align)
{
    return (sys_buf_cache_t)mem_cache_create(name, size, align);
}

static sys_buf_t
BUF_alloc(sys_buf_cache_t const cache, sstring_t whence)
{
    sys_buf_t const ret = mem_cache_alloc_uninit((mem_cache_t)cache);
    mem_buf_allocator_set(ret, whence);
    trace_tooverbose("ALLOC %p length %u by %s", ret, ((mem_cache_t)cache)->buf_size, whence);
    return ret;
}

static sys_buf_t
BUF_zalloc(sys_buf_cache_t const cache, sstring_t whence)
{
    sys_buf_t const ret = mem_cache_alloc((mem_cache_t)cache);
    mem_buf_allocator_set(ret, whence);
    trace_tooverbose("ZALLOC %p length %u by %s", ret, ((mem_cache_t)cache)->buf_size, whence);
    return ret;
}

static void
BUF_hold(sys_buf_t const buf, sstring_t whence)
{
    trace_verbose("HOLD %p by %s", buf, whence);
    mem_hold(buf);
}

static void
BUF_drop(sys_buf_t const buf, sstring_t whence)
{
    trace_tooverbose("DROP %p by %s", buf, whence);
    mem_drop_callerid(buf, whence);
}

static void
BUF_check(sys_buf_t const buf)
{
    mem_check(buf);
}

static errno_t
BUF_cache_destroy(sys_buf_cache_t const cache)
{
    if (!mem_cache_destroy((mem_cache_t)cache)) {
	return EBUSY;
    }
    return E_OK;
}

/******************************************************************************/

extern PER_THREAD uintptr_t sys_stack_end;
PER_THREAD char sys_pthread_name[16];

/* First C function executed on a new thread */
static void *
sys_thread_fn(void * env)
{
    sys_stack_end = (uintptr_t)&env + 0x1000;	    //XXXX
    assert_eq(sys_thread, NULL);
    sys_thread = env;

    assert_eq(sys_thread->tid, 0);
    assert_eq(sys_thread->pthread_id, NULL);
    assert_eq(sys_thread->dob, 0);

    sys_thread->tid = gettid();
    sys_thread->pthread_id = pthread_self();
    sys_thread->dob = NOW();

    sys_notice("thread %s @%p starts up on tid=%u",
	       sys_thread_name(sys_thread_current()), sys_thread, gettid());

    if (sys_thread->name) {
	strncpy(sys_pthread_name, sys_thread->name, sizeof(sys_pthread_name)-1);
	errno_t err = pthread_setname_np(pthread_self(), sys_pthread_name);
	expect_noerr(err, "pthread_setname_np");
    }

    if (CPU_COUNT(&sys_thread->cpu_mask)) {
	errno_t err = pthread_setaffinity_np(pthread_self(),
					     sizeof(cpu_set_t), &sys_thread->cpu_mask);
	expect_noerr(err, "pthread_setaffinity_np");
    }

    int rc;
#if 0
    rc = setpriority(PRIO_PROCESS, sys_thread->tid, sys_thread->nice);
    expect_rc(rc, setpriority, "tid=%u nice=%d", sys_thread->tid, sys_thread->nice);
#endif

    /* The run_fn can either return back to here or call sys_thread_exit():  if it
     * returns back to here it is expected that its stopping thread will clean up
     * after it, after extracting whatever it wants (for example an exit code) --
     * this would typically occur subsequent to some shutdown command sent to the
     * thread being stopped by its stopping thread.
     *
     * If the thread calls sys_thread_exit(), that leads to a pthread_exit(), not
     * returning here.  In that case, the thread structure is freed by sys_thread_exit
     * just before it calls pthread_exit.
     */
    rc = sys_thread->run_fn(sys_thread->run_env);  /* run thread logic */
		    /*** Note that sys_thread may now already no longer exist ***/

    trace("Thread '%s' tid=%u run_fn() returns %d -- thread exits\n",
	  sys_pthread_name, gettid(), rc);

    return NULL;    /* does pthread_exit */
}

/* Start a new thread using an initialized sys_thread_t */
static errno_t
THREAD_start(sys_thread_t thread)
{
    int rc;
    pthread_attr_t attr;
    rc = pthread_attr_init(&attr);
    expect_noerr(rc, "pthread_attr_init");

    /* This lets the thread's stack get cleaned up when it exits */
    rc = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    expect_noerr(rc, "pthread_attr_setdetachstate");
    pthread_t pthread_id;

    sys_notice("thread %s @%p on tid=%u CREATES NEW THREAD %s @%p",
	       sys_thread_name(sys_thread_current()), sys_thread,
	       gettid(), thread->name, thread);

    rc = pthread_create(&pthread_id, &attr, sys_thread_fn, thread);
    if (rc != 0) return -errno;
    expect(pthread_id, "pthread_create");

    rc = pthread_attr_destroy(&attr);
    expect_noerr(rc, "pthread_attr_destroy");

    return E_OK;
}

static sys_thread_t
THREAD_alloc(errno_t (*fn)(void *), void * env, string_t name)
{
    assert(fn);
    sys_thread_t const thread = record_alloc(thread);
    thread->name = name;	    /* we take ownership of name string */
    thread->run_fn = fn;
    thread->run_env = env;
    return thread;
}

static struct sys_thread    MTE_main_thread_space;

/* Called OFF the exited thread -- exclusive with THREAD_exit for a given thread */
static void
THREAD_free(sys_thread_t thread)
{
    verify(thread != &MTE_main_thread_space);
    expect(sys_thread != thread,
	    "Thread '%s' (%u) doing sys_thread_free(itself)",
	    thread->name, thread->tid);

    mem_drop(thread->name);
    record_free(thread);
}

/* Called on the exiting thread -- exclusive with THREAD_free for a given thread */
static void NORETURN
THREAD_exit(int rc)
{
    expect_eq(sys_thread->tid, gettid());
    expect_eq(sys_thread->pthread_id, pthread_self());
    trace("Thread '%s' tid=%u called sys_thread_exit(%d)\n",
	  sys_thread->name, sys_thread->tid, rc);

    if (sys_thread != &MTE_main_thread_space) {
	mem_drop(sys_thread->name);
	record_free(sys_thread);
    }

    sys_thread = NULL;
    pthread_exit(NULL);
}

/******************************************************************************/

/* MTE sys_services state */
typedef struct MTE_system {
    struct sys_service_handle		SYS_S;	    /* embedded */
    uint8_t				ninit;
    uint8_t				nfini;
} * MTE_system_t;

static sys_time_t
SYS_time_now(void)
{
    return MTE_time_now();
}

static struct MTE_system    MTE_space;		/* only need one instance -- it's static */
static MTE_system_t	    MTE = NULL;		/* pointer to single process-wide instance */
static int32mt_t	    MTE_refs = { 0 };

mem_arena_t		    sys_mem_arena = NULL;   /* multithreaded memory arena */

/* SEGV dumps some diagnostic information before process exit */
static void
sigsegv_handler(int const signum, siginfo_t * const siginfo, void * const ucontext_void)
{
    sys_eprintf("\n"); trace_always("******************  SIGSEGV  ******************"); \
    sys_breakpoint();
    sys_signal_dump(signum, siginfo, ucontext_void, "SIGSEGV");
    assert_eq(signum, SIGSEGV);
    sys_panic("SIGSEGV");
}

/* Send SIGSTKFLT to a tid to get the thread to dump a stacktrace */
static void
sigstkflt_handler(int const signum, siginfo_t * const siginfo, void * const ucontext_void)
{
    sys_eprintf("\n"); trace_always("******************  SIGSTKFLT  ******************"); \
    sys_backtrace("SIGSTKFLT");
    assert_eq(signum, SIGSTKFLT);
}

static struct sigaction oldact_segv, oldact_stkflt;

static errno_t
SYS_init(sys_service_cfg_t const v_cfg)
{
    assert_eq(v_cfg, NULL);		/* not presently used */
    if (MTE->ninit) return EINVAL;	/* call only once */
    ++MTE->ninit;

    /* So stack dump knows where to stop when stack is broken */
    sys_stack_end = (uintptr_t)&v_cfg + 0x1000;	    //XXXX FIX

    errno_t err;
    err = pthread_getname_np(pthread_self(), sys_pthread_name, sizeof(sys_pthread_name));
    expect_noerr(err, "pthread_getname_np");
    if (!sys_pthread_name[0]) {
	strncpy(sys_pthread_name, "SYS_init_thread", sizeof(sys_pthread_name)-1);
    }

    /* First set up the thread (neither name nor thread are deallocated for this thread) */
    sys_thread_t t = &MTE_main_thread_space;
    record_zero(t);
    t->run_fn = (void *)SYS_init;	/* only for debugging symbol */
    t->name = sys_pthread_name;
    t->pthread_id = pthread_self();
    t->tid = gettid();
    t->dob = NOW();

    assert_eq(sys_thread, NULL);
    sys_thread = t;

    /* Then set up the memory allocator, which uses thread info */
    sys_mem_arena = mem_arena_create("process memory arena");

    /* Then the event_task module, which uses the memory allocator */
    mte_event_task_init();

    /* Catch some signals (in the usual asynchronous signally way) */
    struct sigaction act;
    int rc;

    act = (struct sigaction) {
	.sa_sigaction = sigsegv_handler,    /* SIGSEGV -- fatal backtrace */
	.sa_mask = { { 0 } },
	.sa_flags = SA_SIGINFO, //XXX | SA_ONSTACK,
    };
    rc = sigaction(SIGSEGV, &act, &oldact_segv);
    if (rc) sys_panic_err(errno, "sigaction(SIGSEGV)");

    act = (struct sigaction) {
	.sa_sigaction = sigstkflt_handler,  /* SIGSTKFLT -- non-fatal backtrace */
	.sa_mask = { { 0 } },
	.sa_flags = SA_SIGINFO,
    };
    rc = sigaction(SIGSTKFLT, &act, &oldact_stkflt);
    if (rc) sys_panic_err(errno, "sigaction(SIGSTKFLT)");

    trace("SYS_init tid=%u\n", sys_thread->tid);
    return E_OK;
}

static errno_t
SYS_fini(void)
{
    if (MTE->nfini >= MTE->ninit) return EINVAL;

    ++MTE->nfini;
    if (MTE->nfini < MTE->ninit) {
	return E_OK;
    }

    mte_event_task_exit();

    string_t stat_str = mem_stats();
    sys_eprintf("\n%s\n", stat_str);
    string_free(stat_str);

    if (mem_arena_destroy(sys_mem_arena) == E_OK) {
	sys_mem_arena = NULL;
    } else {
	sys_warning("Failed to destroy process memory arena"
		    " because memory allocations are still outstanding");
    }

    int rc;
    rc = sigaction(SIGSEGV, &oldact_segv, NULL);
    verify_rc(rc, sigaction);

    rc = sigaction(SIGSTKFLT, &oldact_stkflt, NULL);
    verify_rc(rc, sigaction);

    return E_OK;
}

static void
SYS_dump(sstring_t reason)
{
    // sys_eprintf("sys_dump('%s')\n", reason);
}

static void NORETURN
SYS_abort(void)
{
    static PER_THREAD count_t in_abort = 0;
    ++in_abort;

    if (in_abort <= 3) {
	if (in_abort > 1) {
	    sys_eprintf("RECURSIVE SYS_ABORT -- now active_calls=%u\n", in_abort);
	}
	mte_backtrace("system abort");
	SYS_dump("system abort");
    } else {
	sys_eprintf("RECURSIVE SYS_ABORT -- now active_calls=%u exceeds limit\n", in_abort);
    }

    sys_breakpoint();
    abort();
}

/******************************************************************************/

/* MTE sys_service provider ops vector template */
static struct sys_service_ops const mte_sys_service_ops = {
    .SS_init				= SYS_init,
    .SS_fini				= SYS_fini,
    .SS_dump				= SYS_dump,
    .SS_backtrace			= mte_backtrace,
    .SS_abort				= SYS_abort,

    .SS_time_now			= SYS_time_now,

    /* Implemented in mte_mem.h, mte_mem_impl.h, mte_mem.c */
    .SS_mem_alloc			= MEM_alloc,
    .SS_mem_zalloc			= MEM_zalloc,
    .SS_mem_realloc			= MEM_realloc,
    .SS_mem_free			= MEM_free,

    .SS_buf_cache_create		= BUF_cache_create,
    .BUF_cache_destroy			= BUF_cache_destroy,

    .BUF_alloc				= BUF_alloc,
    .BUF_zalloc				= BUF_zalloc,
    .BUF_hold				= BUF_hold,
    .BUF_drop				= BUF_drop,
    .BUF_check				= BUF_check,

    /* Implemented in mte_thread.c */
    .SS_thread_alloc			= THREAD_alloc,
    .THREAD_start			= THREAD_start,
    .THREAD_exit			= THREAD_exit,
    .THREAD_free			= THREAD_free,

    .SS_etask_alloc			= mte_event_task_alloc,
    .ETASK_fmt				= mte_event_task_fmt,
    .ETASK_run				= mte_event_task_run,
    .ETASK_stop				= mte_event_task_stop,
    .ETASK_free				= mte_event_task_free,

    .ETASK_poll_enable			= mte_poll_enable,
    .ETASK_poll_disable_sync		= mte_poll_disable_sync,
    .ETASK_alarm_set			= mte_alarm_set,
    .ETASK_alarm_cancel_sync		= mte_alarm_cancel_sync,
    .ETASK_callback_schedule		= mte_callback_schedule,
    .ETASK_callback_cancel_sync		= mte_callback_cancel_sync,
    .ETASK_callback_schedule_lopri	= mte_callback_schedule_lopri,
    .ETASK_callback_cancel_lopri_sync	= mte_callback_cancel_lopri_sync,
};

__thread sys_thread_t	    sys_thread = NULL;	    /* instance PER_THREAD */
__thread sys_event_task_t   sys_event_task = NULL;  /* instance PER_THREAD */

/* This could go in sys_debug.h but it is here in a .c file so that it isn't
 * replicated inline in every panic or debug statement.
 */

uint32_t
sys_eprint_prefix_str(char * const buf, uint32_t const buflen)
{
    struct timespec t;
    int rc = clock_gettime(CLOCK_REALTIME, &t);
    expect_rc(rc, clock_gettime,);

    rc = snprintf(buf, buflen, "%"PRIu64".%09"PRIu64" [%u]", t.tv_sec, t.tv_nsec, gettid());
    if (likely(rc >= 0)) return rc;

    strncpy(buf, "(snprintf ERROR)", buflen);
    buf[buflen-1] = '\0';
    return 0;
}

void sys_breakpoint(void) { bp(); }
void bp(void) { }

/* Get MTE sys_service handle (consisting mostly of the ops vector just above) */
sys_service_handle_t
MTE_sys_service_get(void)
{
    if (int32mt_inc(&MTE_refs) == 1) {
	assert_eq(MTE, NULL);
	MTE = &MTE_space;	/* not ready for memory allocator yet */
	sys_service_handle_t const SS = &MTE->SYS_S;
	SS->env = MTE;
	SS->op = mte_sys_service_ops;
    }
    return &MTE->SYS_S;
}

errno_t
MTE_sys_service_put(sys_service_handle_t SS)
{
    assert_eq(MTE, &MTE_space);
    assert_eq(SS, &MTE->SYS_S);

    if (int32mt_dec(&MTE_refs) == 0) {
	if (MTE->nfini < MTE->ninit) {
	    int32mt_inc(&MTE_refs);
	    return EBUSY;
	}
    }

    MTE = NULL;
    return E_OK;
}
