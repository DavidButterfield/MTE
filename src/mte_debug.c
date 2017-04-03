/* mte_debug.c
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Symbols, process memory maps, memory dumps, stacktraces, signal contexts, etc.
 *
 * Note many of these functions are intended for fatal situations and avoid using
 * the memory allocator, returning static strings.
 */
#define NAME MTE_DEBUG
#include <signal.h>
#include <stdio.h>
#include <ctype.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <bits/sigcontext.h>

#include "mte_util.h"
#include "mte_mttypes.h"

PER_THREAD uintptr_t sys_stack_end;

/* Determine whether ascii[0] to ascii[7] look like ASCII characters, if so returning a string
 * with any non-printables fixed up.  Return NULL if it doesn't look like ASCII.
 * The returned string is not freeable.
 */
static count_t contig_is_print_threshold = 4;
static count_t contig_is_common_threshold = 3;

static sstring_t
ascii8_fmt(char * const ascii)
{
    bool good_enough = false;	    /* true if we decide it looks enough like ASCII */

    static PER_THREAD char ret[6+1+8+1+1];	/* extra space for spaces, '[', ']', and '\0' */
    char * rp = ret;						//XXX static return

    *rp++ = ' '; *rp++ = ' '; *rp++ = ' '; *rp++ = ' '; *rp++ = ' '; *rp++ = ' ';
    *rp++ = '[';

    /* Copy one byte at a time from ascii to ret, counting and fixing up non-printables */
    count_t contig_print = 0;
    count_t contig_common = 0;
    idx_t i;
    for (i = 0; i < 8; i++) {
	unsigned char const c = ascii[i];
	bool is_print = false;
	bool is_common = false;

	if (!isprint(c)) {
	    *rp++ = '.';	/* fixup a non-printable character */
	} else {
	    is_print = true;
	    *rp++ = c;		/* copy the character as it is */
	    if (isalnum(c)) {
		is_common = true;
	    } else {
		switch (c) {
		case '_': case '/': case '-': case '.': case '%':
		case '=': case ':': case ',': case '(': case ')':
			is_common = true;

		case '"': case '\'':
		case '!': case '#': case '$': case '*':
		default:
			break;
		}
	    }
	}

	if (is_print) {
	    if (++contig_print >= contig_is_print_threshold) {
		good_enough = true;
	    }
	} else {
	    contig_print = 0;
	}

	if (is_common) {
	    if (++contig_common >= contig_is_common_threshold) {
		good_enough = true;
	    }
	} else {
	    contig_common = 0;
	}
    }

    if (!good_enough) return NULL;  /* doesn't look enough like ASCII */

    *rp++ = ']';
    *rp++ = '\0';

    return ret;
}

    /*  Selected addr2line(1) command-line flags:
     *    -a		display the address (first).
     *    -C		decode (demangle) low-level symbol names into user-level names.
     *    -e filename   filename of the executable for which addresses should be translated.
     *    -f		display function names as well as file and line number information.
     *    -s		display only the base of each file name.
     *    -i		display inline function-calling chains.
     *    -j		read section-relative offsets instead of absolute addresses.
     *    -p		prettier output.
     */

/* Try to lookup a symbol using the addr2line(1) program --
 * lookup failure returns NULL.  The returned string is not freeable.
 */
static sstring_t
sys_symbol_lookup_addr2line(uintptr_t const addr, sstring_t flags)
{
    char cmd_buffer[256];							
    int rc = snprintf(cmd_buffer, sizeof(cmd_buffer),
		      "/usr/bin/addr2line -f -i -s %s -e /proc/%u/exe 0x%"PRIx64,
		      flags, gettid(), addr);
    expect_rc(rc, snprintf);
    assert_le(rc, (int)sizeof(cmd_buffer));

    /* popen returns NULL on failure, with errno set except for memalloc failures (!) */
    errno = 0;
    FILE * pipefile = popen(cmd_buffer, "r");
    if (!pipefile) { perror("popen"); return NULL; }

    static PER_THREAD char ret[4096];				//XXX static return
    ret[0] = '('; ret[1] = 'A'; ret[2] = '2'; ret[3] = ')'; ret[4] = ' ';
    count_t nbytes = 5;
    count_t n;
    while ((n = fread(ret+nbytes, 1, sizeof(ret)-nbytes-1, pipefile))) {
	nbytes += n;
	if (nbytes >= sizeof(ret)-1) {
	    verify_eq(nbytes, sizeof(ret)-1);
	    break;
	}
    }

    assert_be(nbytes, sizeof(ret)-1);
    ret[nbytes] = '\0';
    assert_eq(strlen(ret), nbytes);

    /* pclose() waits for the addr2line process to terminate and returns exit status, or -1 */
    /* on error (exit status 127 is a "hint" that popen *may* have failed to execute shell) */
    int exit_rc = pclose(pipefile);
    __USE(exit_rc); // expect_eq(exit_rc, 0, "pclose");

    /* If addr2line failed to find the symbol, return NULL */
    if (!strncmp(ret+5, "??", 2)) return NULL;

    /* Replace all the newlines in the addr2line output with spaces */
    char *p = ret;
    while (*p) {
	if (*p == '\n') *p = ' ';
	p++;
    }

    return ret;
}

/* Try to lookup a symbol using the backtrace_symbols(3) library function --
 * lookup failure returns NULL.  The returned string is not freeable.
 */
static sstring_t
sys_symbol_lookup_backtrace(uintptr_t addr)
{
    char * * const symp = backtrace_symbols((void *)&addr, 1);
    if (symp) {
	char * const sym = *symp;
	if (*sym != '[') {
	    /* take it */
	    char * p = sym;
	    while (*p) {
		if (*p == '[') {
		    *p = '\0';
		    break;
		}
		p++;
	    }
	    /* found a symbol -- return it */
	    static PER_THREAD char buf[256];		//XXX static return
	    snprintf(buf, sizeof(buf), "(BT) %s", sym);
	    free(symp);
	    return buf;
	}
	free(symp);
    }
    return NULL;
}

/* Try to lookup a symbol using the dladdr(3) library function --
 * lookup failure returns NULL.  The returned string is not freeable.
 */
static sstring_t
sys_symbol_lookup_dladdr(uintptr_t const addr)
{
    Dl_info dli;
    record_zero(&dli);

    /* dladdr returns 0 on error, nonzero on success */
    int rc = dladdr((void *)addr, &dli);
    if (rc == 0) return NULL;
    if (!dli.dli_sname) return NULL;
    if (!dli.dli_saddr) return NULL;
 
    static PER_THREAD char buf[256];			//XXX static return
 
    rc = snprintf(buf, sizeof(buf), "(DL) %s + %lu",
				    dli.dli_sname, addr - (uintptr_t)dli.dli_saddr);
    expect_rc(rc, snprintf);
    assert_le(rc, sizeof(buf)-1);
    return buf;
}

#define SMALL_INTEGER (64*1024UL)	/* Smaller than this isn't an address */

/* Try to lookup a symbol from its address using various methods --
 * addr is often just a value seen in memory during a dump, so there is not
 * necessarily any indication that addr is, in fact, intended to be an address.
 * Part of the job here, then, is to determine that question.
 * The returned string is not freeable.
 */
static sstring_t
sys_symbol_nostack(uintptr_t addr)
{
    int32_t addr_hi = (addr >> 32) & 0xffffffff;
    int32_t addr_lo = addr & 0xffffffff;

    /* If we recognize a small integer -- which has no symbol -- return an empty string */
    if (addr_hi < 0x7fff && addr_lo <= (int)SMALL_INTEGER) {
	//XXX could return decimal string for 64-bit small integers (positive or negative)
	return "";  /* small integer, or a pair of small 32-bit integers */
    }

    sstring_t sym = NULL;

    //XXXX should be subtracting one from TEXT RETURN addresses

    /* Try to lookup the address using addr2line(1) */
    sym = sys_symbol_lookup_addr2line(addr, "");
    if (sym) return sym;

    /* Try to lookup the address using addr2line(1) */
    // sym = sys_symbol_lookup_addr2line(addr, "-j");	//XXX need section
    // if (sym) return sym;

    /* Try to lookup the address using backtrace_symbols(3) */
    sym = sys_symbol_lookup_backtrace(addr);
    if (sym) return sym;

    /* Try to lookup the address using dladdr(3) */
    sym = sys_symbol_lookup_dladdr(addr);
    if (sym) return sym;

    /* See if it looks like ASCII characters */
    sym = ascii8_fmt((char *)&addr);  /* look at "addr" as 8 characters instead */
    if (sym) return sym;

    return NULL;    /* didn't recognize the addr as anything interesting */
}

/* Try to get a symbol assuming addr is a virtual address in the program */
sstring_t
sys_symbol(uintptr_t const addr)
{
    sstring_t sym = sys_symbol_nostack(addr);
    if (sym) return sym;	/* got something, return that */

    return "";    /* didn't recognize the addr as anything interesting */
}

/* Try to get a string describing the specified address -- like sys_symbol,
 * but also prints the offsets of stack addresses from the given SP and BP
 */
sstring_t
sys_symbol_stack_ref(uintptr_t const addr, uintptr_t const SP, uintptr_t const BP)
{
    /* First try the methods above before resorting to offsets from SP */
    sstring_t const sym = sys_symbol_nostack(addr);
    if (sym) return sym;	/* got something, return that */

    /* Didn't get a hit on symbol lookup and it doesn't look like ASCII...
     * see if it might look like an address on the stack
     */
    if (SP <= SMALL_INTEGER) return "";

    /* XXX should get the stack segment from the process map -- in the meantime, hack this:
     *     check a range starting somewhere below our fault SP and ending somewhere above it */
    uintptr_t const stackmin = ROUNDDOWN(SP, 0x2000); 
    uintptr_t const stackmax = sys_stack_end;
    bool const a_refers_to_stack = addr >= stackmin && addr < stackmax;

    if (a_refers_to_stack) {
	static PER_THREAD char ret[256];			//XXX static return
	ssize_t const sp_delta = addr - SP;
	bool const bp_refers_to_stack = BP >= stackmin && BP < stackmax;
	if (bp_refers_to_stack) {
	    ssize_t const bp_delta = addr - BP;
	    int pos = snprintf(ret, sizeof(ret), "[SP+%08x (%ld)]",
						 (uint32_t)sp_delta, sp_delta);
	    snprintf(ret+pos, sizeof(ret)-pos, "%*s[BP+%08x (%ld)]", 25-pos, " ",
						 (uint32_t)bp_delta, bp_delta);
	} else {
	    snprintf(ret, sizeof(ret), "[SP+%08x (%ld)]", (uint32_t)sp_delta, sp_delta);
	}
	return ret;
    }

    return "";    /* didn't recognize the addr as anything interesting */
}

/* Format and return a stack function-call backtrace previously acquired */
string_t
sys_backtrace_fmt(void * bt[], count_t const nframes)
{
    char buf[8192];
    record_zero(buf);		/* avoid cruft in stacktrace output */

    char * pos = buf;		/* current output position (in buf) */
    count_t space = sizeof(buf);/* space remaining from pos to end of buf */
    idx_t idx;
    for (idx = 0; idx < nframes && space > 1; idx++) {
	int rc = snprintf(pos, space, " [%02u] %18p  %s\n",
			    idx, bt[idx], sys_symbol((uintptr_t)bt[idx]-1));
	expect_rc(rc, "snprintf");
	pos += rc;
	space -= rc;
    }

    return sstring_copy(buf);
}

/* Format and dump a stack function-call backtrace previously acquired */
void
sys_backtrace_dump(void * bt[], count_t const nframes)
{
    pid_t my_tid = gettid();
    idx_t idx;
    for (idx = 0; idx < nframes; idx++) {
	sys_eprintf(" %u [%02u] %18p  %s\n",
		    my_tid, idx, bt[idx], sys_symbol((uintptr_t)bt[idx]-1));
    }
}

/* Fill bt with up to max return addresses from the current calling stack */
count_t
sys_backtrace_get_max(void * bt[], count_t const stackframes_max)
{
    return backtrace(bt, stackframes_max);
}

extern PER_THREAD char sys_pthread_name[16];

/* Generate and print a stack function-call backtrace from the current stack frame --
 * does not use the memory allocator
 */
void
mte_backtrace(sstring_t const reason)
{
    char _se_prefix[64];
    sys_eprint_prefix_str(_se_prefix, sizeof(_se_prefix));
    sys_eprintf("%s BACKTRACE pid=%d tid=%u '%s' due to %s\n",
		_se_prefix, getpid(), gettid(), sys_pthread_name, reason);
    sys_eprintf( "                          * * * * * * * * * * * * * * * * * * * * \n");

    if (!valgrind_is_active()) {
	void * bt[100];
	uint32_t const nframes = sys_backtrace_get_max(bt, NELEM(bt));
	sys_backtrace_dump(bt, nframes);
    } else {
	valgrind_backtrace("%s", reason);
    }

    sys_eprintf( "                          * * * * * * * * * * * * * * * * * * * * \n");
}

/* Dump to stderr a memory range covering the addresses [start, end) --
 * if SP is non-zero, use it as the base for displaying relative SP addresses; also BP.
 */
#define DUMP_PER_ROW_MAX 8
void
mem_dump_stack(uintptr_t const start, uintptr_t const end, uintptr_t const SP,
				      uintptr_t const BP, string_t const reason)
{
    /* Maybe expand the range slightly to start and end on cache-line boundaries */
    uintptr_t const round_start = ROUNDDOWN(start, CACHE_ALIGN_BYTES);
    uintptr_t round_end = ROUNDUP(end, CACHE_ALIGN_BYTES);

    if (round_end < round_start) {
	round_end = round_start + 0x4000;
    }

    count_t const nword32 = (round_end - round_start) / sizeof(uint32_t);
    uint32_t * p32 = (void *)round_start;

    sys_eprintf("Dump %p to %p -- %s", (void *)round_start, (void *)round_end, reason);

    /* Default to looking up symbols */
    bool do_sym = true;		/* flag denoting whether we are dumping symbols */
    count_t dump_per_row = 2;		/* number of 32-bit words to dump per output line */

    char * env_do_sym = getenv("MEM_DUMP_SYMBOLS");
    if (env_do_sym) {
	char c = *env_do_sym;
	if (c == '0' || c == 'f' || c == 'F' || c == 'n' || c == 'N') {
	    /* no symbols -- configure to gang up several words onto each line */
	    do_sym = false;
	    dump_per_row = DUMP_PER_ROW_MAX;
	}
	else if (c == '1' || c == 't' || c == 'T' || c == 'y' || c == 'Y') {
	    /* use defaults set above */
	} else {
	    sys_warning("Unrecognized value of getenv(\"MEM_DUMP_SYMBOLS\"): %s", env_do_sym);
	}
    }

    sstring_t sym_str = "";
    string_t str = NULL;
    idx_t word32n;
    bool dump_this_row = true;
    for (word32n = 0; word32n < nword32; word32n++, p32++) {
	if (word32n % dump_per_row == 0) {		/* time to start a new line */
	    /* put a little mark where the SP and BP point */
	    sstring_t pre_str;
	    if (SP >= (uintptr_t)p32 && SP < (uintptr_t)p32 + dump_per_row * sizeof(*p32)) {
		pre_str = "SP>";
		dump_this_row = true;
	    } else if (BP >= (uintptr_t)p32 && BP < (uintptr_t)p32 + dump_per_row * sizeof(*p32)) {
		pre_str = "BP>";
		dump_this_row = true;
	    } else {
		/* dump any line that will display a non-zero value */
		pre_str = "   ";
		dump_this_row = false;
		idx_t lookahead;
		for (lookahead = 0; lookahead < dump_per_row &&
					    word32n + lookahead < nword32; lookahead++) {
		    if (p32[lookahead] != 0) {
			dump_this_row = true;
			break;
		    }
		}
	    }
	    if (dump_this_row) {
		/* append previous line's SYMBOL, and the ADDRESS for the new line starting; */
		/* pre_str is either an SP or BP indicator, or a spacer of the same width */
		str = sys_sprintf_append(str, "   %s\n%s%p: ", sym_str, pre_str, p32);
		/* save the symbol for the line we're starting, to print at the end of line */
		if (do_sym) sym_str = sys_symbol_stack_ref(*(uintptr_t *)p32, SP, BP);
	    }
	}
	if (dump_this_row) {
	    /* append output for another 32-bit word in the current line */
	    str = sys_sprintf_append(str, " 0x%08x", *p32);
#ifndef REALLY_LONG_OUTPUT_STRINGS
	    sys_eprint_str_plain(str);
	    string_free_null(str);
	    str = NULL;
#endif
	}
    }

    str = sys_sprintf_append(str, "   %s\n   %p", sym_str, p32);
    sys_eprint_str_plain(str);
    string_free_null(str);
}

void
mem_dump(uintptr_t const start, uintptr_t const end, string_t const reason)
{
    mem_dump_stack(start, end, 0, 0, reason);
}

/******************************************************************************/

/* Format fault information for SIGILL, SIGFPE, SIGSEGV, SIGBUS, and SIGTRAP */
static void
fault_info_fmt_noalloc(char * const buf, len_t const buflen,
		       siginfo_t const * const si, sstring_t const whence)
{
    snprintf(buf, buflen,
	    "%s: addr=%p lsb=%u",
	    whence, si->si_addr, si->si_addr_lsb);
} 

/* Format a (freeable) human-readable string for the source of a signal */
static string_t
siginfo_fmt(siginfo_t const * const si)
{
    int const si_signo = si->si_signo;
    int const si_errno = si->si_errno;	/* "generally unused on Linux" */
    int const si_code = si->si_code;

    /* si_codes applicable to any signal */
    sstring_t code_str = "";
    char code_info_str[256] = { [0] = '\0' };

    switch (si_code) {
    case SI_QUEUE:	code_str = "sigqueue(3)";
			snprintf(code_info_str, sizeof(code_info_str),
				"sigqueue={pid=%u uid=%u int=%u ptr=%p}",
				si->si_pid, si->si_uid, si->si_int, si->si_ptr);
			break;

    case SI_TIMER:	code_str = "timer expiration";
			snprintf(code_info_str, sizeof(code_info_str),
				"timer={sigval=%p/%u si_overrun=%u id=%u}",
				si->si_value.sival_ptr, si->si_value.sival_int,
				si->si_overrun, si->si_timerid);
			break;

    case SI_SIGIO:	code_str = "queued SIGIO/SIGPOLL";
			snprintf(code_info_str, sizeof(code_info_str),
				"SIGIO/SIGPOLL={si_band=%lu si_fd=%u}",
				si->si_band, si->si_fd);
			break;

    case SI_USER:	code_str = "kill, raise, or sigsend";
			snprintf(code_info_str, sizeof(code_info_str),
				"killer={pid=%u uid=%u}",
				si->si_pid, si->si_uid);
			break;

    case SI_KERNEL:	code_str = "generation by kernel";		break;
    case SI_MESGQ:	code_str = "mq_notify(3) state change";		break;
    case SI_TKILL:	code_str = "tkill(2)/tgkill(2) system call";	break;
    case SI_ASYNCIO:    code_str = "AIO completion";			break;
    default:		if (si_code <= 0) {
			    code_str = "XXX BAD negative siginfo si_code XXX";
			}
			break;
    }

    /* The meanings of other si_codes depend on their generating signal type.
     *
     * Note that the signal-specific error code sets below overlap with each
     * other, but not with the si_codes processed above
     */
    char sig_info_str[256] = { [0] = '\0' };
    sstring_t sig_str = "";

    switch (si_signo) {
    case SIGILL:
	switch (si_code) {
	case ILL_ILLOPC: sig_str = "illegal opcode";			break;
	case ILL_ILLOPN: sig_str = "illegal operand";			break;
	case ILL_ILLADR: sig_str = "illegal addressing mode";		break;
	case ILL_ILLTRP: sig_str = "illegal trap";			break;
	case ILL_PRVOPC: sig_str = "privileged opcode";			break;
	case ILL_PRVREG: sig_str = "privileged register";		break;
	case ILL_COPROC: sig_str = "coprocessor error";			break;
	case ILL_BADSTK: sig_str = "internal stack error";		break;
	default: break;
	}
	fault_info_fmt_noalloc(sig_info_str, sizeof(sig_info_str), si, "SIGILL");
	break;

    case SIGFPE:
	switch (si_code) {
	case FPE_INTDIV: sig_str = "integer divide by zero";		break;
	case FPE_INTOVF: sig_str = "integer overflow";			break;
	case FPE_FLTDIV: sig_str = "floating point divide by zero";	break;
	case FPE_FLTOVF: sig_str = "floating point overflow";		break;
	case FPE_FLTUND: sig_str = "floating point underflow";		break;
	case FPE_FLTRES: sig_str = "floating point inexact result";	break;
	case FPE_FLTINV: sig_str = "floating point invalid operation";	break;
	case FPE_FLTSUB: sig_str = "subscript out of range";		break;
	default: break;
	}
	fault_info_fmt_noalloc(sig_info_str, sizeof(sig_info_str), si, "SIGFPE");
	break;

    case SIGSEGV:
	switch (si_code) {
	case SEGV_MAPERR: sig_str = "address not mapped to object";	break;
	case SEGV_ACCERR: sig_str = "invalid permissions for object";	break;
	default: break;
	}
	fault_info_fmt_noalloc(sig_info_str, sizeof(sig_info_str), si, "SIGSEGV");
	break;

    case SIGBUS:
	switch (si_code) {
	case BUS_ADRALN:    sig_str = "invalid address alignment";	break;
	case BUS_ADRERR:    sig_str = "non-existent physical address";	break;
	case BUS_OBJERR:    sig_str = "object-specific hardware error";	break;
	case BUS_MCEERR_AR: sig_str = "hardware memory error consumed";	break;
	case BUS_MCEERR_AO: sig_str = "hardware memory error detected";	break;
	default: break;
	}
	fault_info_fmt_noalloc(sig_info_str, sizeof(sig_info_str), si, "SIGBUS");
	break;

    case SIGTRAP:
	switch (si_code) {
	case TRAP_BRKPT:    sig_str = "process breakpoint";		break;
	case TRAP_TRACE:    sig_str = "process trace trap";		break;
	//XXX case TRAP_BRANCH:   sig_str = "process taken branch trap";	break;
	//XXX case TRAP_HWBKPT:   sig_str = "hardware break/watch point";	break;
	default: break;
	}
	fault_info_fmt_noalloc(sig_info_str, sizeof(sig_info_str), si, "SIGTRAP");
	break;

    case SIGCHLD:
	switch (si_code) {
	case CLD_EXITED:    sig_str = "child has exited";		break;
	case CLD_KILLED:    sig_str = "child was killed";		break;
	case CLD_DUMPED:    sig_str = "child terminated abnormally";	break;
	case CLD_TRAPPED:   sig_str = "traced child has trapped";	break;
	case CLD_STOPPED:   sig_str = "child has stopped";		break;
	case CLD_CONTINUED: sig_str = "stopped child has continued";	break;
	default: break;
	}
	snprintf(sig_info_str, sizeof(sig_info_str),
				"SIGCHLD={pid=%u uid=%u rc=%u utime=%lu stime=%lu",
				si->si_pid, si->si_uid, si->si_status,
				si->si_utime, si->si_stime);
	break;

    case SIGPOLL:
	switch (si_code) {
	case POLL_IN:	    sig_str = "data input available";		break;
	case POLL_OUT:	    sig_str = "output buffers available";	break;
	case POLL_MSG:	    sig_str = "input message available";	break;
	case POLL_ERR:	    sig_str = "I/O error";			break;
	case POLL_PRI:	    sig_str = "high-priority input available";	break;
	case POLL_HUP:	    sig_str = "device disconnected";		break;
	default: break;
	}
	snprintf(sig_info_str, sizeof(sig_info_str),
				"SIGPOLL={fd=%u band=%lu", si->si_fd, si->si_band);
	break;

    case SIGSYS:
	switch (si_code) {
	//XXX case SYS_SECCOMP:   sig_str = "seccomp triggered";		break;
	default: break;
	}
	snprintf(sig_info_str, sizeof(sig_info_str),
			    "SIGSYS={call_addr=%p syscall=%u arch=%u",
			    si->si_call_addr, si->si_syscall, si->si_arch);
	break;

    default: break;
    }

    expect(*code_str == '\0' || *sig_str == '\0');    /* one or the other */

    //XXX maybe change this to not require any memory allocation
    string_t ret = sys_sprintf(
			"sig=%u err=%u code=%d (due to %s%s) %s %s",
			si_signo, si_errno, si_code,
			code_str, sig_str, code_info_str, sig_info_str);
    return ret;
}

/* General registers in desired order of printing */
#define UCONTEXT_GREGS_ITEMS()		\
/*     index id, dump_string, want_decimal */   \
  ITEM( REG_RIP,     ip,	false	    )	\
  ITEM( REG_CR2,     cr2,	true	    )	\
  ITEM( REG_ERR,     err,	true	    )	\
  ITEM( REG_TRAPNO,  trapno,	true	    )	\
						\
  ITEM( REG_RSP,     sp,	false	    )	\
  ITEM( REG_RBP,     bp,	true/*gcc*/ )	\
  ITEM( REG_RSI,     rsi,	true	    )	\
  ITEM( REG_RDI,     rdi,	true	    )	\
						\
  ITEM( REG_RAX,     ax,	true	    )	\
  ITEM( REG_RBX,     bx,	true	    )	\
  ITEM( REG_RCX,     cx,	true	    )	\
  ITEM( REG_RDX,     dx,	true	    )	\
						\
  ITEM( REG_R8,	     r8,	true	    )	\
  ITEM( REG_R9,	     r9,	true	    )	\
  ITEM( REG_R10,     r10,	true	    )	\
  ITEM( REG_R11,     r11,	true	    )	\
						\
  ITEM( REG_R12,     r12,	true	    )	\
  ITEM( REG_R13,     r13,	true	    )	\
  ITEM( REG_R14,     r14,	true	    )	\
  ITEM( REG_R15,     r15,	true	    )	\
						\
  ITEM( REG_EFL,     eflags,	false	    )	\
  ITEM( REG_CSGSFS,  cs/gs/fs,	false	    )	\
  ITEM( REG_OLDMASK, oldmask,	false	    )	\

/* List of ucontext gpregs[] indexes and printable names */
#define ITEM(_idx, _name, want)	{ .idx = _idx, .name = #_name, .want_decimal = want},
static struct {
    idx_t		idx;
    sstring_t		name;
    bool		want_decimal;
} const regname[] = {
    UCONTEXT_GREGS_ITEMS()
};
#undef ITEM

static string_t
ucontext_fmt(ucontext_t * const ucontext)
{
    ucontext_t * uc = ucontext;
    string_t ret = NULL;

    do {
	ret = sys_sprintf_append(ret,
		    "usermode_context={ uc_flags=0x%lx fpregs@%p sigstack=%p/0x%lx ss_flags=0x%x }",
		    uc->uc_flags, uc->uc_mcontext.fpregs,
		    uc->uc_stack.ss_sp, uc->uc_stack.ss_size, uc->uc_stack.ss_flags);
	idx_t idx;

	/* Print a line for each CPU general register in the list above */
	for (idx = 0; idx < NELEM(regname); idx++) {
	    if (regname[idx].want_decimal) {
		ret = sys_sprintf_append(ret,
			    "\n  %8s = 0x%016llx %21lld  %s",
			    regname[idx].name, uc->uc_mcontext.gregs[regname[idx].idx],
			    uc->uc_mcontext.gregs[regname[idx].idx], 
			    sys_symbol_stack_ref(uc->uc_mcontext.gregs[regname[idx].idx],
					         uc->uc_mcontext.gregs[REG_RSP],
					         uc->uc_mcontext.gregs[REG_RBP]));
	    } else {
		/* IP, SP, BP, etc in decimal is more clutterly than it is useful */
		ret = sys_sprintf_append(ret,
			    "\n  %8s = 0x%016llx %21s  %s",
			    regname[idx].name, uc->uc_mcontext.gregs[regname[idx].idx],
			    " ",
			    sys_symbol_stack_ref(uc->uc_mcontext.gregs[regname[idx].idx],
					         uc->uc_mcontext.gregs[REG_RSP],
					         uc->uc_mcontext.gregs[REG_RBP]));
	    }
	}

	uc = uc->uc_link;   /* there could be a chain of these */
    } while (uc);

    return ret;
}

static sys_spinlock_t sys_abort_lock;	/* avoid mixing dump output from multiple threads */

/* Dump out diagnostic information after a signal */
void
sys_signal_dump(int const signum, siginfo_t * const siginfo, ucontext_t * const ucontext,
								string_t const whence)
{
    expect_eq(signum, siginfo->si_signo);

    sys_spin_lock(&sys_abort_lock);	/* avoid mixing dump output from multiple threads */

    sys_backtrace("fatal signal");

    /* signal information */
    string_t const siginfo_str = siginfo_fmt(siginfo);
    sys_eprintf("%s: %s\n", whence, siginfo_str);
    string_free(siginfo_str);

    /* user context information */
    string_t const ucontext_str = ucontext_fmt(ucontext);
    sys_eprintf( "%s\n\n", ucontext_str);
    string_free(ucontext_str);

#ifndef VALGRIND
    uintptr_t const SP = ucontext->uc_mcontext.gregs[REG_RSP];
    uintptr_t const BP = ucontext->uc_mcontext.gregs[REG_RBP];
    mem_dump_stack(ROUNDDOWN(SP, CACHE_ALIGN_BYTES), sys_stack_end, SP, BP, "fault stack");
#endif

    fflush(stderr);

    sys_spin_unlock(&sys_abort_lock);
}

static bool
sys_tcp_info(int const sock_fd, struct tcp_info * const info)
{
    size_t len = sizeof(*info);
    sys_rc_t const rc = sock_getopt(sock_fd, IPPROTO_TCP, TCP_INFO, info, &len);
    return (rc == SYS_RC_OK);
}

static string_t
sys_tcp_info_fmt(struct tcp_info * const ti)
{
    return sys_sprintf(
	"state=0x%x ca_state=0x%x retrans=%u probes=%u backoff=%u options=0x%x"
	" snd_wscale=%u rcv_wscale=%u rto=%u ato=%u snd_mss=%u rcv_mss=%u"
	" unacked=%u sacked=%u lost=%u retrans=%u fackets=%u last_data_sent=%u"
	"\n\t\tlast_ack_sent=%u last_data_recv=%u last_ack_recv=%u"
	" pmtu=%u rcv_ssthresh=%u rtt=%u rttvar=%u snd_ssthresh=%u snd_cwnd=%u"
	" advmss=%u reordering=%u rcv_rtt=%u rcv_space=%u total_retrans=%u",
	ti->tcpi_state, ti->tcpi_ca_state, ti->tcpi_retransmits, ti->tcpi_probes,
	    ti->tcpi_backoff, ti->tcpi_options,
	ti->tcpi_snd_wscale, ti->tcpi_rcv_wscale, ti->tcpi_rto, ti->tcpi_ato,
	    ti->tcpi_snd_mss, ti->tcpi_rcv_mss,
	ti->tcpi_unacked, ti->tcpi_sacked, ti->tcpi_lost, ti->tcpi_retrans, ti->tcpi_fackets,
	    ti->tcpi_last_data_sent,
	ti->tcpi_last_ack_sent, ti->tcpi_last_data_recv, ti->tcpi_last_ack_recv,
	ti->tcpi_pmtu, ti->tcpi_rcv_ssthresh, ti->tcpi_rtt, ti->tcpi_rttvar,
	    ti->tcpi_snd_ssthresh, ti->tcpi_snd_cwnd,
	ti->tcpi_advmss, ti->tcpi_reordering, ti->tcpi_rcv_rtt, ti->tcpi_rcv_space,
	    ti->tcpi_total_retrans);
}

string_t
sys_tcp_info_get_fmt(int const sock_fd)
{
    struct tcp_info info;
    bool const ok = sys_tcp_info(sock_fd, &info);
    if (ok) {
        return sys_tcp_info_fmt(&info);
    } else {
        return sstring_copy("sock_getopt(sock_fd, IPPROTO_TCP, TCP_INFO) failed");
    }
}
