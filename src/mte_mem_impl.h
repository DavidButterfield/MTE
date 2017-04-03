/* mte_mem_impl.h
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Implementation-private inline functions for fast memory allocator
 */
#ifndef MTE_MEM_H
#error mte_mem_impl.h is only intended for inclusion from mte_mem.h
#endif

#include "mte_util.h"	    /* above the guard to enforce #inclusion order */
#ifndef MTE_MEM_IMPL_H
#define MTE_MEM_IMPL_H
#include <string.h>

#include "mte_mttypes.h"

#define MEM_ALIGN_MIN			CACHE_ALIGN_BYTES
#define MEM_ALIGN_SECTOR		SECTOR_ALIGN_BYTES
#define MEM_ALIGN_MAX			PAGE_ALIGN_BYTES

/* The ~7 helps catch cases where the bottom bits are not part of the pointer and
   get changed by some helper -- we can still recognize pattern in higher bits */
#if !OPTIMIZED
#define BADPTR(ptr) (	((uintptr_t)(ptr) & ~7ul) == (MEM_PATTERN_ALLOC_64 & ~7ul) || \
			((uintptr_t)(ptr) & ~7ul) == (MEM_ZAP_64 & ~7ul)    )
#else
#define BADPTR(ptr)			false
#endif

#define assert_ptr(ptr)			assert((ptr) != NULL && !BADPTR(ptr), \
					       "BAD POINTER %p", (ptr))

#define verify_ptr(ptr)			verify((ptr) != NULL && !BADPTR(ptr), \
					       "BAD BUFFER POINTER %p", (ptr))

typedef struct _mem_hdr		      * mem_hdr_t;	/* header for each mem_alloc() */
string_t				mem_hdr_fmt(mem_hdr_t const hdr);

typedef struct mem_arena	      * mem_arena_t;	/* a set of mem_caches */
mem_arena_t				mem_arena_create(sstring_t const name);
errno_t					mem_arena_destroy(mem_arena_t const arena);
string_t				mem_arena_fmt(mem_arena_t const arena);

extern void buf_info(buf_t);		/* dump header info for a buffer */

/* Memory buffer patterns detect some instances of memory corruption -- generation and checking
 * of patterns is enabled by default in DEBUG builds, disabled by default in OPTIMIZED builds.
 *
 * Primarily used with free-buffer caches to monitor "idle" buffers for changes while free.
 *
 * When a buffer is FREED, all its usable space is written with a pattern.  Upon ALLOCATION for
 * the next re-use of the buffer, the buffer is checked for any deviations from the pattern
 * (which imply memory corruption, most likely a WRITE-AFTER-FREE error by the previous owner).
 *
 * The pattern is contrived to be unlikely as a valid pointer, in the hope of inducing earlier
 * failure in a USE-AFTER-FREE error (e.g. if the use was to fetch a pointer for dereferencing).
 * The pattern is also unlikely as a "small integer", and is easily recognizable under gdb(1).
 *
 * When a buffer is ALLOCATED, any SURPLUS space at the end of the buffer (beyond the size
 * being requested) is written with a pattern.  Upon FREE of the buffer, that SURPLUS area at
 * the end of the buffer is checked for any deviations from the pattern, which imply memory
 * corruption (most likely a BUFFER-OVERRUN error by the owner doing the free).
 *
 * A returned buffer may have surplus space at the end due to size or alignment rounding; this
 * can range from ZERO bytes to a maximum nearly half the size of the buffer.  By default, DEBUG
 * builds provide an ADDITIONAL "redzone" margin of surplus bytes at the end of every memory
 * allocation (i.e. there is always some non-zero minimum surplus when that is enabled).  All
 * allocations have a minimum size-alignment to improve the efficiency of pattern set/check.
 *
 * Oversize buffers are returned to the backing allocator, so we won't be checking them upon
 * re-use from there -- but we zap them with the pattern (when enabled) anyway before freeing
 * them, for the sake of code consistency, inducing earlier failure for some USE-AFTER-FREE
 * errors, and recognizability under gdb(1).
 */

/* Check nwords 64-bit words of aligned memory starting at ptr for deviations from a pattern --
 * nwords may be zero -- ptr must be 8-byte aligned -- Return true if OK, false if deviation.
 */
static inline bool
mem_check_aligned_words(uint64_t const * const ptr_in,
			uint64_t const pattern64, llen_t const nwords)
{
    assert(IS_PTR_ALIGNED(ptr_in));
    register uint64_t * ptr = ASSUME_ALIGNED(ptr_in, PTR_ALIGN_BYTES);
    register llen_t nchunks = nwords / 16;
    register len_t const n_oddwords = nwords % 16;
    register int error = 0;

    while (nchunks--) {
	if (unlikely((*(ptr+0)  != pattern64) |
		     (*(ptr+1)  != pattern64) |
		     (*(ptr+2)  != pattern64) |
		     (*(ptr+3)  != pattern64) |
		     (*(ptr+4)  != pattern64) |
		     (*(ptr+5)  != pattern64) |
		     (*(ptr+6)  != pattern64) |
		     (*(ptr+7)  != pattern64) |
		     (*(ptr+8)  != pattern64) |
		     (*(ptr+9)  != pattern64) |
		     (*(ptr+10) != pattern64) |
		     (*(ptr+11) != pattern64) |
		     (*(ptr+12) != pattern64) |
		     (*(ptr+13) != pattern64) |
		     (*(ptr+14) != pattern64) |
		     (*(ptr+15) != pattern64))) {
	    return false;
	}
	ptr += 16;
    }

    switch (n_oddwords) {
    default:
    case 15: error |= *(ptr+14) != pattern64;
    case 14: error |= *(ptr+13) != pattern64;
    case 13: error |= *(ptr+12) != pattern64;
    case 12: error |= *(ptr+11) != pattern64;
    case 11: error |= *(ptr+10) != pattern64;
    case 10: error |= *(ptr+9)  != pattern64;
    case 9:  error |= *(ptr+8)  != pattern64;
    case 8:  error |= *(ptr+7)  != pattern64;
    case 7:  error |= *(ptr+6)  != pattern64;
    case 6:  error |= *(ptr+5)  != pattern64;
    case 5:  error |= *(ptr+4)  != pattern64;
    case 4:  error |= *(ptr+3)  != pattern64;
    case 3:  error |= *(ptr+2)  != pattern64;
    case 2:  error |= *(ptr+1)  != pattern64;
    case 1:  error |= *(ptr+0)  != pattern64;
    case 0: break;
    }

    return !error;
}

typedef union {
    uint8_t	    const * p8;
    uint8_t		  * pw8;
    uint16_t	    const * p16;
    uint16_t		  * pw16;
    uint32_t	    const * p32;
    uint32_t		  * pw32;
    uint64_t	    const * p64;
    uint64_t		  * pw64;
    uintptr_t		    u64;
} mem_alloc_union_t;

/* Check the pattern in nbytes of END-aligned memory starting at ptr --
 * nbytes may be zero -- the specified memory area must END on an 8-byte boundary;
 * returns false if a deviation from the pattern is seen; true if OK.
 */
static inline bool
mem_check_endaligned(uint8_t * const ptr, uint8_t const val, llen_t const nbytes)
{
    assert(IS_PTR_ALIGNED(ptr + nbytes));   /* end-aligned */
    mem_alloc_union_t p = { .p8 = ptr };
    uint64_t const val64 = val * 0x0101010101010101ull;
    uint32_t nbytes_at_start = -p.u64 % 8;

    if (unlikely(nbytes_at_start > 0)) {
	/* Check up to 7 odd bytes at the start of the memory area */
	if (unlikely(nbytes_at_start > nbytes)) {
	    nbytes_at_start = nbytes;	/* avoid exceeding a tiny nbytes */
	}
#if !defined(__i386__) && !defined(__x86_64__)
        #warning XXX unaligned access, endian dependency
#endif
	uint64_t mask = (1 << (nbytes_at_start*8) ) - 1; /* nbytes low bytes of 0xff */
	if ((*p.p64 & mask) != (val64 & mask)) return false;
	p.p8 += nbytes_at_start;
    }

    /* check the remaining (aligned) bytes as words */
    assert(IS_PTR_ALIGNED(p.p8));
    return mem_check_aligned_words(p.p64, val64, nbytes / 8);
}

/* Set nwords 64-bit words to val64 starting at ptr, which must be 8-byte aligned */
/* More efficient when ptr aligned */
#define rep_stosq(ptr, val64, nwords)						\
do {										\
    void * _rdi_out;								\
    uint64_t _rcx_out;								\
    asm volatile (								\
	    /* "cld\n\t" */							\
	    "rep\n\t"								\
	    "stosq\n\t"								\
	    : "=D" (_rdi_out),	    /* not really outputs: */			\
	      "=c" (_rcx_out) 	    /*     convince compiler not to "assume" */	\
	    : "a" (val64),          /* inputs: byte value to be set at ptr */	\
	      "0" (ptr),	    /*         destination start address */	\
	      "1" (nwords)	    /*         number of bytes to set at ptr */	\
	    :			    /* no additional clobbered registers */	\
	    );									\
} while (0)

/* Set nwords (<=32) 64-bit words to val64 starting at ptr, which must be 8-byte aligned */
static always_inline void
mem_set_aligned64(uint64_t * const ptr, uint64_t const val64, lcount_t const nwords)
{
    assert(IS_PTR_ALIGNED(ptr));
    uint64_t * p = ASSUME_ALIGNED(ptr, PTR_ALIGN_BYTES);
    assert(IS_CONSTANT(nwords));
    assert_be(nwords, 32);

    /* Performance drops off quickly doing more than 256 bytes this way, but between 40 bytes
     * and 256 bytes this is faster than memset().  At 40 bytes and below memset() uses a
     * similar optimization resulting in similar performance.
     *
     * Note all these conditionals are evaluated at compile-time, leaving only the necessary
     * subset of assignments here at runtime.
     */
    if (nwords >=  1) *(p +  0) = val64;
    if (nwords >=  2) *(p +  1) = val64;
    if (nwords >=  3) *(p +  2) = val64;
    if (nwords >=  4) *(p +  3) = val64;
    if (nwords >=  5) *(p +  4) = val64;
    if (nwords >=  6) *(p +  5) = val64;
    if (nwords >=  7) *(p +  6) = val64;
    if (nwords >=  8) *(p +  7) = val64;
    if (nwords >=  9) *(p +  8) = val64;
    if (nwords >= 10) *(p +  9) = val64;
    if (nwords >= 11) *(p + 10) = val64;
    if (nwords >= 12) *(p + 11) = val64;
    if (nwords >= 13) *(p + 12) = val64;
    if (nwords >= 14) *(p + 13) = val64;
    if (nwords >= 15) *(p + 14) = val64;
    if (nwords >= 16) *(p + 15) = val64;
    if (nwords >= 17) *(p + 16) = val64;
    if (nwords >= 18) *(p + 17) = val64;
    if (nwords >= 19) *(p + 18) = val64;
    if (nwords >= 20) *(p + 19) = val64;
    if (nwords >= 21) *(p + 20) = val64;
    if (nwords >= 22) *(p + 21) = val64;
    if (nwords >= 23) *(p + 22) = val64;
    if (nwords >= 24) *(p + 23) = val64;
    if (nwords >= 25) *(p + 24) = val64;
    if (nwords >= 26) *(p + 25) = val64;
    if (nwords >= 27) *(p + 26) = val64;
    if (nwords >= 28) *(p + 27) = val64;
    if (nwords >= 29) *(p + 28) = val64;
    if (nwords >= 30) *(p + 29) = val64;
    if (nwords >= 31) *(p + 30) = val64;
    if (nwords >= 32) *(p + 31) = val64;
}

/* Write a pattern into nwords 64-bit words of aligned memory starting at ptr --
 * nwords may be zero -- ptr must be 8-byte aligned
 */
static always_inline void
mem_set_aligned_words(uint64_t * const ptr, uint64_t const val64, lcount_t const nwords)
{
    assert(IS_PTR_ALIGNED(ptr));	    /* start-aligned */
    uint64_t * p = ASSUME_ALIGNED(ptr, PTR_ALIGN_BYTES);

    if (IS_CONSTANT(nwords) && nwords <= 32) {
	mem_set_aligned64(p, val64, nwords);
    } else {
	rep_stosq(p, val64, nwords);
    }
}

/* Set nbytes to val starting at ptr, which must be 8-byte aligned --
 *
 * Above 8192 bytes memset() uses non-temporal (cache-bypassing) store instructions,
 * which are faster than rep_stosq() above around 200 bytes.  We handle sizes <= 256
 * bytes using mem_set_aligned64() just above.
 *
 * However rep_stosq() (unexpectedly) becomes about 40% faster than memset() > 4MB sizes.
 */
#define mem_zero_startaligned(ptr, nbytes) mem_set_startaligned((ptr), 0, (nbytes))
static always_inline void *
mem_set_startaligned(void * const ptr, uint8_t const val, lcount_t const nbytes)
{
    assert(IS_PTR_ALIGNED(ptr));	    /* start-aligned */
    mem_alloc_union_t p = { .p8 = ASSUME_ALIGNED(ptr, PTR_ALIGN_BYTES) };

    if (!IS_CONSTANT(nbytes)) {
	/* Number of words not known at compile-time -- just use memset() */
	memset(p.pw8, val, nbytes);
	return ptr;		/* memset did any odd bytes */
    }

    uint64_t const val64 = val * 0x0101010101010101ull;

    /* These conditionals are evaluated at compile-time */
    if (nbytes < 33*8) {
	/* Here we are setting a total of 263 or fewer bytes (32*8 + 4 + 2 + 1) */
	mem_set_aligned64(p.pw64, val64, nbytes/8);
    }
    else if (nbytes <= 4*MEGA) {
	/* Below 8192 bytes the compiler "optimizes" memset() by using rep stos rather than the
	 * non-temporal (NT) instructions -- the use of the volatile here tricks the compiler into
	 * always using the faster NT version.
	 */
	lcount_t volatile vnb = nbytes;
	memset(p.pw8, val, vnb);
	return ptr;		/* memset did any odd bytes */
    }
    else {
	/* 4MB and above this measures faster than memset() on my Core 2 Quad */
	rep_stosq(p.pw64, val64, nbytes/8);
    }

    /* Do any odd bytes at the end */
    count_t const nbytes_at_end = nbytes % 8;
    if (!IS_CONSTANT(nbytes_at_end) || nbytes_at_end > 0) {
	p.p64 += nbytes/8;
	if (nbytes_at_end & 4) *p.pw32++ = val64;
	if (nbytes_at_end & 2) *p.pw16++ = val64;
	if (nbytes_at_end & 1) *p.pw8++ = val64;
    }

    return ptr;
}

/* Set nbytes to val starting at ptr (any alignment) */
#define mem_zero(ptr, nbytes) mem_set((ptr), 0, (nbytes))
static always_inline void *
mem_set(void * const ptr, uint8_t const val, lcount_t const nbytes)
{
    assert_be(nbytes, TYPE_MAXI(size_t));
    mem_alloc_union_t p = { .p8 = ptr };

    uint32_t nbytes_at_start = -p.u64 % 8;
    if (unlikely(nbytes_at_start > 0)) {
	/* ptr is an unaligned starting address -- fill until 64-bit aligned */
	if (unlikely(nbytes_at_start > nbytes)) {
	    /* If this happens it thwarts the assignment alignment just below,
	     * but I'm not expecting many calls to set tiny unaligned buffers,
	     * and x86 CPUs can correctly execute misaligned for some cycle cost.
	     */
	    nbytes_at_start = nbytes;	    /* nbytes is really small */
	}
	uint32_t const val32 = val * 0x01010101UL;
	if (nbytes_at_start & 1) *p.pw8++ = val32;
	if (nbytes_at_start & 2) *p.pw16++ = val32;
	if (nbytes_at_start & 4) *p.pw32++ = val32;
    }

    mem_set_startaligned(p.pw8, val, nbytes - nbytes_at_start);

    return ptr;
}

/* Copy nwords (<=32) 64-bit words from src to dst; both must be 8-byte aligned */
static always_inline void
mem_copy_aligned64(uint64_t * const dst, uint64_t const * const src, lcount_t const nwords)
{
    assert(IS_PTR_ALIGNED(src));
    uint64_t const * const s = ASSUME_ALIGNED(src, PTR_ALIGN_BYTES);
    assert(IS_PTR_ALIGNED(dst));
    uint64_t * const d = ASSUME_ALIGNED(dst, PTR_ALIGN_BYTES);

    assert(IS_CONSTANT(nwords));
    assert_be(nwords, 32);

    /* Note all these conditionals are evaluated at compile-time, leaving only the necessary
     * subset of copies here at runtime.
     */
    if (nwords >=  1) *(d +  0) = *(s +  0);
    if (nwords >=  2) *(d +  1) = *(s +  1);
    if (nwords >=  3) *(d +  2) = *(s +  2);
    if (nwords >=  4) *(d +  3) = *(s +  3);
    if (nwords >=  5) *(d +  4) = *(s +  4);
    if (nwords >=  6) *(d +  5) = *(s +  5);
    if (nwords >=  7) *(d +  6) = *(s +  6);
    if (nwords >=  8) *(d +  7) = *(s +  7);
    if (nwords >=  9) *(d +  8) = *(s +  8);
    if (nwords >= 10) *(d +  9) = *(s +  9);
    if (nwords >= 11) *(d + 10) = *(s + 10);
    if (nwords >= 12) *(d + 11) = *(s + 11);
    if (nwords >= 13) *(d + 12) = *(s + 12);
    if (nwords >= 14) *(d + 13) = *(s + 13);
    if (nwords >= 15) *(d + 14) = *(s + 14);
    if (nwords >= 16) *(d + 15) = *(s + 15);
    if (nwords >= 17) *(d + 16) = *(s + 16);
    if (nwords >= 18) *(d + 17) = *(s + 17);
    if (nwords >= 19) *(d + 18) = *(s + 18);
    if (nwords >= 20) *(d + 19) = *(s + 19);
    if (nwords >= 21) *(d + 20) = *(s + 20);
    if (nwords >= 22) *(d + 21) = *(s + 21);
    if (nwords >= 23) *(d + 22) = *(s + 22);
    if (nwords >= 24) *(d + 23) = *(s + 23);
    if (nwords >= 25) *(d + 24) = *(s + 24);
    if (nwords >= 26) *(d + 25) = *(s + 25);
    if (nwords >= 27) *(d + 26) = *(s + 26);
    if (nwords >= 28) *(d + 27) = *(s + 27);
    if (nwords >= 29) *(d + 28) = *(s + 28);
    if (nwords >= 30) *(d + 29) = *(s + 29);
    if (nwords >= 31) *(d + 30) = *(s + 30);
    if (nwords >= 32) *(d + 31) = *(s + 31);
}

/* Copy nwords 64-bit words of aligned memory from src to dst --
 * nwords may be zero -- src and dst must be 8-byte aligned
 */
static always_inline void
mem_copy_aligned_words(uint64_t * const dst, uint64_t const * const src, lcount_t const nwords)
{
    assert(IS_PTR_ALIGNED(src));
    uint64_t const * const s = ASSUME_ALIGNED(src, PTR_ALIGN_BYTES);
    assert(IS_PTR_ALIGNED(dst));
    uint64_t * const d = ASSUME_ALIGNED(dst, PTR_ALIGN_BYTES);

    if (IS_CONSTANT(nwords) && nwords <= 32) {
	mem_copy_aligned64(d, s, nwords);
    } else {
	memcpy(d, s, nwords*8);
    }
}

/* Copy nwords 64-bit words of aligned memory from src to dst --
 * nwords may be zero -- src and dst must be 8-byte aligned.
 * (src and dst do not have to be buffers allocated with mem_alloc)
 */
static always_inline void
mem_copy(void * const dst, void const * const src, lcount_t const nbytes)
{
    if (    IS_CONSTANT(IS_PTR_ALIGNED(src)) && IS_PTR_ALIGNED(src) &&
	    IS_CONSTANT(IS_PTR_ALIGNED(dst)) && IS_PTR_ALIGNED(dst)) {
	mem_copy_aligned64((uint64_t *)dst, (uint64_t const *)src, nbytes/8);
    } else {
	memcpy(dst, src, nbytes);
    }
}

#if OPTIMIZED	    /* mem_alloc_pattern and mem_alloc_redzone disable */
  /* Disabling this #define at compile-time results in more efficient code */
  #define mem_alloc_pattern_enabled() false   /* This omits patterns from the compiled code */
  #define mem_alloc_redzone_enabled() false   /* This omits redzones from the compiled code */
#else
  /* Enable or disable monitoring of "idle" memory for changes, which indicate corruption */
  #define mem_alloc_pattern_enabled() mem_alloc_pattern_flag
  extern bool mem_alloc_pattern_flag;

  /* Disabling this #define at compile-time results in more efficient code */
  /* Enable or disable allocation of unused (but checked) memory just after each buffer */
  #define mem_alloc_redzone_enabled() mem_alloc_redzone_flag
  extern bool mem_alloc_redzone_flag;
#endif

/* Return a buffer size adjusted upward from nominal to leave at least a minimum amount of
 * SURPLUS buffer space at the end of each allocation -- depending on sizes and alignment,
 * there is likely more than the minimum amount of surplus space -- all surplus space is
 * subject to pattern-checking, when enabled.
 *
 * Page-aligned allocations will have at least enough surplus space to fill out the remainder
 * of the last page used by the allocation (i.e. nothing else will be allocated sharing a page
 * with a page-aligned allocation).
 *
 * The returned "total" size does *not* include the header located before the returned buffer.
 */
static inline llen_t
mem_buf_size_total(llen_t const size, llen_t const align, bool const redzone)
{
    /* Every allocation we make has a minimum size alignment to ease pattern checking */
    if (!redzone) return ROUNDUP(size, MEM_ALIGN_MIN);

    /* Include some extra "redzone" space at the end of each allocation */
    if (align >= MEM_ALIGN_MAX)	    return ROUNDUP(size+512, MEM_ALIGN_MAX);
    if (align >= MEM_ALIGN_SECTOR)  return ROUNDUP(size+512, MEM_ALIGN_SECTOR);
    if (size  >= MEM_ALIGN_MAX)     return ROUNDUP(size+512, MEM_ALIGN_SECTOR);
				    return ROUNDUP(size+64,  MEM_ALIGN_MIN);
}

/***** Primordial Allocator *****/

#define WARNING_SIZE (MEM_ALIGN_MAX + mem_buf_size_total(16*MEGA, MEM_ALIGN_MAX, true))

#define posix_alloc(nbytes) posix_alloc_aligned(nbytes, (llen_t)MEM_ALIGN_MIN)

static inline void *
posix_alloc_aligned(llen_t const nbytes, llen_t const align)
{
    assert_be(nbytes, TYPE_MAXI(size_t));
    assert_ae(align, CACHE_ALIGN_BYTES);
    assert_be(align, PAGE_ALIGN_BYTES);
    if (DEBUG && nbytes > WARNING_SIZE) {   /* warn about large allocations */
	sys_warning("large allocation of %"PRIu64" bytes\n", nbytes);
	sys_backtrace("large allocation");
    }
    void * ptr;
    int const rc = posix_memalign(&ptr, align, nbytes);
    assert_eq(rc, 0);
    assert_ptr(ptr);
    assert(IS_CACHE_ALIGNED(ptr), "%p", ptr);
    return ASSUME_ALIGNED(ptr, CACHE_ALIGN_BYTES);
}

static inline void
posix_drop(void const * const ptr)
{
    assert_ptr(ptr);
    free(unconstify(ptr));
}

static inline void
posix_free(void const * const ptr, llen_t const nbytes)
{
    assert_be(nbytes, TYPE_MAXI(size_t));
    posix_drop(ptr);
}

/***** Memory allocation header -- keeps refcount and debugging info for each buffer *****/

/* Backing allocator for mem_hdr allocations (and frees, in the case of uncached allocations) */
/* NB: mem_hdr_backalloc() does not clear the allocated memory */
#define mem_hdr_backalloc(total_size, align)	posix_alloc_aligned((total_size), (align))
#define mem_hdr_backfree(ptr, total_size)	posix_free((ptr), (total_size))

/* Debugging aid: seqno for each alloc and free, monotonic across all caches/threads */
extern int64mt_t mem_hdr_seqno;

/* Header just ahead of each allocated (or cached) buffer (64 bytes) --
 * A buffer is "allocated" if its refcount is non-zero.
 */
typedef struct _mem_hdr {
    uint16_t		    magic;		/* corruption detection */
    uint8_t		    align	    :7;	/* buffer alignment in units of MEM_ALIGN_MIN */
      uint8_t		    destructing	    :1;	/* marked for free to backing allocator */
    bool		    cache_owned	    :1;	/* owner is a mem_cache */
      bool		    size_4k	    :1;	/* size_inuse in 4KB units (SYS_ALLOC_HUGE) */
      uint8_t		    spare_4	    :4;
      bool		    redzone	    :1;	/* redzone area exists & written with pattern */
      bool		    pattern	    :1;	/* free or surplus area written with pattern */
    int32mt_t		    refcount;		/* number of references on buffer (0-->free) */

    len_t		    size_inuse;		/* last allocation request size (see size_4k) */
    uint16_t	            alloc_tasknum;	/* tasknum of last allocating task */
    uint16_t	            free_tasknum;	/* tasknum of last freeing task */

    count_t	   volatile alloc_seqno;	/* sequence number of last allocation */
    count_t	   volatile free_seqno;		/* sequence number of last free */

    mem_cache_t		    parent;		/* pointer to parent object, e.g. cache */

    sstring_t		    alloc_caller;	/* last allocating caller */

    sstring_t		    free_caller;	/* last freeing caller */

    sys_link_t		    parent_link;	/* for use by parent cache or other object */

    sys_link_t		    free_link;		/* when free (e.g. cache freelist) */
} * mem_hdr_t;

#define MEM_HDR_SIZE		    sizeof(struct _mem_hdr)
#define MEM_HDR_MAGIC		    0xa10c	/* first short of header (~"alloc") */
#define MEM_PATTERN_GAP		    0xbb	/* pattern in gap before header "blank" */

struct mem_cache {
    /* Unchanging after creation of cache */
    magic_t		    magic;		/* corruption detection */
    bool		    trace;		/* debug trace enable */
    sstring_t		    name;		/* human observability */
    len_t		    buf_size;		/* usable size of buffers in this cache */
    len_t		    buf_align;		/* alignment of buffers in this cache */
    /* Current state */
    sys_freelist_t	    freelist;		/* list of cached free buffers */
    sys_fifo_t		    mem_hdr_list;	/* list of cache-owned allocations */
    bool		    destructing;	/* for checking */
    int32mt_t		    nexist;		/* number of allocations into cache */
    int64mt_t		    nalloc;		/* number of allocations from cache */
};

#define MEMCACHE_MAGIC		0x4ECA4ECA	/* "FREE CAche FREE CAche" */

/* Return a buffer's header */
static always_inline mem_hdr_t
mem_hdr_of_buf(void const * c_buf)
{
    void * buf = unconstify(c_buf);
    verify_ptr(buf);
#if !OPTIMIZED
    verify(IS_CACHE_ALIGNED(buf), "%p", buf);
#endif
    return buf - MEM_HDR_SIZE;
}

/* Return a header's buffer */
static always_inline buf_t
mem_hdr_to_buf(mem_hdr_t const hdr)
{
    assert_ptr(hdr);
    assert(IS_CACHE_ALIGNED(hdr), "%p", hdr);
    return (buf_t)hdr + MEM_HDR_SIZE;
}

static always_inline void
_mem_buf_allocator_set(void const * const buf, sstring_t const caller_id)
{
    mem_hdr_t const hdr = mem_hdr_of_buf(buf);
    hdr->alloc_caller = caller_id;
}

static always_inline void
mem_hdr_alignment_set(mem_hdr_t const hdr, uint32_t const align)
{
    assert(IS_CACHE_ALIGNED(hdr), "%p", hdr);
    assert(IS_CACHE_ALIGNED(align), "%u", align);
    assert_be(align, MEM_ALIGN_MAX, "%u", align);
    assert_eq(hdr->align, 0);	/* not set yet */
    hdr->align = align / MEM_ALIGN_MIN;
    assert_eq(hdr->align, align / MEM_ALIGN_MIN);   /* check overflow */
}

static always_inline uint32_t
mem_hdr_alignment(mem_hdr_t const hdr)
{
    return hdr->align * MEM_ALIGN_MIN;
}

/* Return the usable size of the buffer */
static always_inline llen_t
mem_hdr_size_usable(mem_hdr_t const hdr)
{
    if (likely(hdr->cache_owned)) return hdr->parent->buf_size;
    return hdr->size_inuse * (1 + (hdr->size_4k * 4095));
}

static always_inline llen_t
mem_buf_size_usable(buf_t buf)
{
    return mem_hdr_size_usable(mem_hdr_of_buf(buf));
}

/* Set the currently-allocated size of the buffer */
static always_inline void
mem_hdr_size_inuse_set(mem_hdr_t const hdr, llen_t const size_inuse)
{
    if (hdr->cache_owned) assert_be(size_inuse, mem_hdr_size_usable(hdr));

#if !MEM_ALLOC_HUGE
    assert_be(size_inuse, VAR_MAXI(hdr->size_inuse) - 1);
    hdr->size_inuse = size_inuse;
    assert_eq(hdr->size_inuse, size_inuse);
#else
    if (likely(size_inuse < VAR_MAXI(hdr->size_inuse))) {
	hdr->size_inuse = size_inuse;
	assert_eq(hdr->size_inuse, size_inuse);
    } else {
	hdr->size_4k = true;
	hdr->size_inuse = size_inuse / PAGE_ALIGN_BYTES;
	assert_eq(hdr->size_inuse, size_inuse / PAGE_ALIGN_BYTES);
    }
#endif
}

/* Return the currently-allocated size of the buffer */
static always_inline llen_t
mem_hdr_size_inuse(mem_hdr_t const hdr)
{
#if !MEM_ALLOC_HUGE
    assert(!hdr->size_4k);
    return hdr->size_inuse;
#else
    if (unlikely(hdr->size_4k)) {
	return hdr->size_inuse * PAGE_ALIGN_BYTES;
    } else {
	return hdr->size_inuse;
    }
#endif
}

static always_inline llen_t
mem_buf_size_inuse(void const * const buf)
{
    return mem_hdr_size_inuse(mem_hdr_of_buf(buf));
}

/* Declare a memory header or buffer area to be corrupted (panics) */
sstring_t NORETURN mem_hdr_corrupt(mem_hdr_t const hdr, buf_t buf, string_t const info);

/* Check a mem_hdr_t */
static always_inline void
mem_hdr_check(mem_hdr_t const hdr)
{
    verify_ptr(hdr);
    verify_eq(hdr->magic, MEM_HDR_MAGIC, "%s", mem_hdr_corrupt(hdr, mem_hdr_to_buf(hdr),
		    "BAD MAGIC on memory buffer"));
    assert(!hdr->destructing);
    assert_eq(hdr->spare_4, 0);

    assert_be(mem_hdr_size_inuse(hdr), mem_hdr_size_usable(hdr));
    assert(IS_ALIGNED((void const *)mem_hdr_to_buf(hdr), mem_hdr_alignment(hdr)));

    assert_imply(hdr->cache_owned, hdr->parent);

    assert_be(hdr->alloc_seqno, (unsigned)int64mt_get(&mem_hdr_seqno));
    assert_be(hdr->free_seqno, (unsigned)int64mt_get(&mem_hdr_seqno));

#if DEBUG   /* mem_hdr_seqno range checking (limited to the first 4G alloc/frees */
    /* Only compare the hdr seqnos while the master seqno is still within their range */
    if (int64mt_get(&mem_hdr_seqno) <= VAR_MAXI(hdr->alloc_seqno)) {
	assert_eq_bool(int32mt_get(&hdr->refcount) > 0, hdr->alloc_seqno > hdr->free_seqno);
    }
#endif
}

/* Check a mem_hdr_t expected to be in allocated state */
static inline void
mem_hdr_check_allocated(mem_hdr_t const hdr)
{
    mem_hdr_check(hdr);
    assert_ge(int32mt_get(&hdr->refcount), 1, "%s", mem_hdr_corrupt(hdr, mem_hdr_to_buf(hdr),
			  "Zero refcount on 'allocated' buffer ((probable double-free)"));

    /* If a pattern was written when this buffer was allocated, check it */
    if (mem_alloc_pattern_enabled() && hdr->pattern) {
	/* Check surplus and redzone buffer space for pattern deviations */
	len_t const align = mem_hdr_alignment(hdr);
	llen_t const pattern_len =
		mem_buf_size_total(mem_hdr_size_usable(hdr), align, hdr->redzone)
								- mem_hdr_size_inuse(hdr);
	if (!mem_check_endaligned(mem_hdr_to_buf(hdr) + mem_hdr_size_inuse(hdr),
						      MEM_PATTERN_ALLOC, pattern_len)) {
	    mem_hdr_corrupt(hdr, mem_hdr_to_buf(hdr), "probable write past end of buffer");
	}
    }
}

/* Check a mem_hdr_t expected to be in free state */
static inline void
mem_hdr_check_free(mem_hdr_t const hdr)
{
    mem_hdr_check(hdr);
    assert_eq(int32mt_get(&hdr->refcount), 0, "%s", mem_hdr_corrupt(hdr, mem_hdr_to_buf(hdr),
							"nonzero refcount on 'free' buffer"));

    /* If a pattern was written when this buffer was freed, check it for any changes */
    if (mem_alloc_pattern_enabled() && hdr->pattern) {
	/* Pattern was written -- check the entire buffer for deviations */
	len_t const align = mem_hdr_alignment(hdr);
	if (!mem_check_aligned_words(mem_hdr_to_buf(hdr), MEM_PATTERN_ALLOC_64,
		     mem_buf_size_total(mem_hdr_size_usable(hdr), align, hdr->redzone) / 8)) {
	    mem_hdr_corrupt(hdr, mem_hdr_to_buf(hdr), "probable write after free");
	}
    }
}

/* Move a buffer from free-state to allocated-state, applying one reference hold */
static inline void
mem_hdr_set_allocated(mem_hdr_t const hdr, llen_t const size_req, sstring_t const caller_id)
{
    mem_hdr_check_free(hdr);	    /* buffer should be in free-state to begin with */

    int32_t const nref = int32mt_inc(&hdr->refcount);
    assert_eq(nref, 1);		    /* fresh allocation from expected zero refcount */

    /* Set the header fields to reflect the buffer being in allocated-state */
    mem_hdr_size_inuse_set(hdr, size_req);
    hdr->alloc_tasknum = sys_thread_num(sys_thread);
    hdr->alloc_caller = caller_id;
    hdr->alloc_seqno = int64mt_inc(&mem_hdr_seqno);

    /* Check whether or not we are writing an alloc-surplus pattern... */
    if (mem_alloc_pattern_enabled()) {
	/* ...and if so, fill the surplus area beyond the requested size with the pattern */
	/* (OK to write over the end of the buffer area) */
	llen_t const size_usable = mem_hdr_size_usable(hdr);
	buf_t const buf = mem_hdr_to_buf(hdr);
	void * const addr_aligned = buf + ROUNDDOWN(size_req, 8);
	len_t const len_words = (buf + size_usable - addr_aligned) / 8;
	mem_set_aligned_words(addr_aligned, MEM_PATTERN_ALLOC_64, len_words);
	hdr->pattern = true;
    } else {
	hdr->pattern = false;
    }

    mem_hdr_check_allocated(hdr);   /* ensure in good allocated-state */
    trace_tooverbose("                         [%s ALLOC %p %"PRIu64"]", caller_id, hdr, size_req);
}

/* Apply another reference hold on this header's memory buffer --
 * the free occurs when the initial allocation and each hold has been matched by a free.
 *
 * mem_hdr_refhold returns the address of the buffer -- for compatibility with raw posix
 * allocations, which may copy the buffer, upon return the caller should associate one
 * of its references with the returned buffer address, while another reference continues
 * its association with the address passed into mem_hdr_refhold().  This only matters for
 * testing.  If the caller really cares, it can compare the returned address with the
 * passed address and assert they are the same if it needs a real reference on the original.
 *
 * The code here is in the mem_hdr implementation, so it always takes a reference.  The
 * raw posix memory allocator implementation may do the copy mentioned here.
 */
static inline buf_t
mem_hdr_refhold(mem_hdr_t const hdr, sstring_t const caller_id)
{
    mem_hdr_check_allocated(hdr);   /* ensure in good allocated-state */
    int32_t const nrefs = int32mt_inc(&hdr->refcount);
    assert_ge(nrefs, 2);	    /* Must be holding it already to take another hold */
    trace_verbose("                         [%s HOLD  %p %"PRIu64"]",
		     caller_id, hdr, mem_hdr_size_inuse(hdr));
    return mem_hdr_to_buf(hdr);
}

/* Decrement the buffer's refcount and transition to free-state if it has reached zero --
 *
 * If hdr->pattern is set, pattern_len is the SURPLUS size (in bytes) ending at the end of the
 * full usable space belonging to the buffer, beyond the size_req number of bytes actually
 * requested by the allocating caller and specified again (for checking) by our freeing caller.
 * Deviation from the pattern within those bytes is a detection of data corruption (most likely
 * BUFFER-OVERRUN by the buffer's owner, but possibly WRITE-AFTER-FREE by a previous owner, or
 * some random pointer corruption).
 *
 * If add_pattern is set, then as part of this free the buffer will be filled with a pattern,
 * which may be checked if/when the buffer is allocated for its next re-use.  (This is runtime
 * selectable as it is too useful to entirely omit from OPTIMIZED builds -- on by default in
 * DEBUG builds).
 *
 * Returns true if this was the last reference; otherwise false.  If this was the last
 * reference, caller is responsible for disposing or caching of the freed buffer.
 */
static inline bool
mem_hdr_refdrop(mem_hdr_t const hdr, sstring_t const caller_id)
{
    mem_hdr_check_allocated(hdr);	/* buffer should be in allocated state */

    int32_t const nref = int32mt_dec(&hdr->refcount);
    if (unlikely(nref > 0)) {
	trace_tooverbose("                         [%s DROP  %p %"PRIu64"]",
			 caller_id, hdr, mem_hdr_size_inuse(hdr));
	return false;	    /* other reference holds remain */
    }

    /* All references are gone -- carry on with marking the buffer as free */
    assert_eq(nref, 0);

    /* Set the header fields to reflect the buffer moving into free-state
			       (leaving hdr->size_inuse as debugging information) */
    hdr->free_tasknum = sys_thread_num(sys_thread);
    hdr->free_caller = caller_id;
    hdr->free_seqno = int64mt_inc(&mem_hdr_seqno);

    /* Check whether or not we are writing a free-pattern... */
    if (mem_alloc_pattern_enabled()) {
	/* ...and if so, fill the buffer space with the pattern
		(Note allocations are size-aligned, and it's OK to run over into surplus) */
	buf_t const buf = mem_hdr_to_buf(hdr);
	llen_t const size_inuse = mem_hdr_size_inuse(hdr);
	mem_set_aligned_words(buf, MEM_PATTERN_ALLOC_64, (size_inuse+7) / 8);
	hdr->pattern = true;
    } else {
	hdr->pattern = false;
    }

    mem_hdr_check_free(hdr);	    /* ensure we leave it in good free-state */
    trace_tooverbose("                         [%s FREE  %p %"PRIu64"]",
		     caller_id, hdr, mem_hdr_size_inuse(hdr));
    return true;
}

/***** memory freelist cache -- caches one size of free buffers *****/

/* Return a header and its buffer TO THE BACKING ALLOCATOR */
void mem_hdr_free(mem_hdr_t const hdr);

/* Allocate a NEW aligned buffer and its header FROM THE BACKING ALLOCATOR --
 * the header is initialized to free-state; the buffer itself remains UNinitialized */
mem_hdr_t mem_hdr_alloc(llen_t const buf_size, llen_t const buf_align);

static always_inline void
mem_cache_check(mem_cache_t const cache)
{
    mem_check(cache);
    assert_eq(cache->magic, MEMCACHE_MAGIC);
    assert_is_bool(cache->trace);
    assert(cache->name);
    assert(cache->buf_size);
    assert_ae(cache->buf_align, 8);
    assert_be(cache->buf_align, MEM_ALIGN_MAX);
    assert(is_power_of_2(cache->buf_align));
}

/* Allocate a buffer from the specified free-buffer cache --
 * size_req is used for checking:  it may be less than the capacity of a cache element,
 *				   but must be matched by the (eventual) _free(size_req)
 */
static inline mem_hdr_t
_mem_cache_alloc(mem_cache_t const cache, llen_t const size_req, sstring_t const caller_id)
{
    mem_cache_check(cache);
    assert(!cache->destructing);
    assert_be(size_req, cache->buf_size);
    int64mt_inc(&cache->nalloc);

    /* first look in the free-buffer cache */
    mem_hdr_t hdr = sys_freelist_take_entry(&cache->freelist, mem_hdr_t, free_link);
    if (unlikely(!hdr)) {
	/* nothing available in freelist -- get a new one */
	hdr = mem_hdr_alloc(cache->buf_size, cache->buf_align);
	hdr->cache_owned = true;
	hdr->parent = cache;
#ifndef VALGRIND
	sys_fifo_append(&cache->mem_hdr_list, &hdr->parent_link);
#endif
	int32mt_inc(&cache->nexist);
#if !OPTIMIZED	    /* cache->trace ignored/disabled in fully OPTIMIZED builds */
	if (cache->trace) {
	    trace_always("cache[%p:%s] %s hdr=%p = alloc(%"PRIu64") NEW alloc A%u",
					cache, cache->name, caller_id, hdr, size_req,
					(uint32_t)(1+mem_hdr_seqno.i));
	}
    } else {
	assert(hdr->cache_owned);
	assert_eq(hdr->parent, cache);
	if (cache->trace) {
	    trace_always("cache[%p:%s] %s hdr=%p = alloc(%"PRIu64") from cache A%u",
					cache, cache->name, caller_id, hdr, size_req,
					(uint32_t)(1+mem_hdr_seqno.i));
	}
#endif
    }

    assert_eq(mem_hdr_size_usable(hdr), cache->buf_size);

    mem_hdr_set_allocated(hdr, size_req, caller_id);
    return hdr;
}

/* Free a buffer to its free-buffer cache */
//XXX implement a limitation on the number of free items cached */
static inline void
_mem_cache_free(mem_hdr_t const hdr, llen_t const size_req, sstring_t const caller_id)
{
    bool const last_ref = mem_hdr_refdrop(hdr, caller_id);
    if (unlikely(!last_ref)) return;

    /* Only examine cache_owned/parent when refcount zero, to avoid cache destruction race */
    assert(hdr->cache_owned);
    mem_cache_t const cache = hdr->parent;
    mem_cache_check(cache);

    assert_be(size_req, cache->buf_size);
    assert_eq(mem_hdr_size_usable(hdr), cache->buf_size);
    assert_eq(mem_hdr_size_inuse(hdr), size_req);

  #if !OPTIMIZED    /* cache->trace ignored/disabled in fully OPTIMIZED builds */
    if (unlikely(cache->trace)) {
	trace_always("cache[%p:%s] %s hdr=%p = xfree(%"PRIu64") A%u F%u",
		     cache, cache->name, caller_id, hdr, size_req,
		     hdr->alloc_seqno, (uint32_t)(1+mem_hdr_seqno.i));
    }
  #endif

#ifdef VALGRIND
    /* Always free back to backing allocator under valgrind */
    mem_hdr_free(hdr);
    int32mt_dec(&cache->nexist);
#else
    /* Return the buffer to its cache */
    sys_freelist_add(&cache->freelist, &hdr->free_link);
#endif
}

/***** Per-thread arena keeps mem_caches of various sizes for general allocation *****/

#define ARENA_MIN_BITS		CACHE_ALIGN_BITS
#define ARENA_MIN_BYTES		((llen_t)1 << ARENA_MIN_BITS)

#define ARENA_MAX_BITS		24	/* 16M of usable page-aligned buffer space */

#define ARENA_MAX_BYTES		((llen_t)1 << ARENA_MAX_BITS)

#define ARENA_FREELISTS		(ARENA_MAX_BITS - ARENA_MIN_BITS + 1)

typedef struct mem_arena {
    magic_t		    magic;		/* corruption detection */
    mem_cache_t		    cache[ARENA_FREELISTS];
    struct {
	int32mt_t	    nallocs;		/* number of oversize allocations */
	int32mt_t	    nfrees;		/* number of oversize frees */
    } oversize;
} * mem_arena_t;

typedef struct mem_arena * mem_arena_t;
extern mem_arena_t sys_mem_arena;

static always_inline mem_arena_t
my_arena(void)
{
    return sys_mem_arena;
}

#define MEM_ARENA_MAGIC 0x4E4E4E4E		/* "FREE FREE FREE FREE" */

static inline void
mem_arena_check(mem_arena_t const arena)
{
    assert_eq(arena->magic, MEM_ARENA_MAGIC);
    assert_be(int32mt_get(&arena->oversize.nfrees), int32mt_get(&arena->oversize.nallocs));

    idx_t i;
    for (i = 0; i < NELEM(arena->cache); i++) {
	mem_cache_check(arena->cache[i]);
    }
}

/* usable buffer size for the given freelist index */
#define mem_arena_index_size(idx) ((llen_t)ARENA_MIN_BYTES << (idx))

/* compute the freelist index for smallest buffers with the needed number of bytes */
static always_inline int
_mem_arena_index(llen_t const size_req)
{
    /* Smallest allocation at cache[0] typically gets > 50% of allocation requests */
    if (likely(size_req <= ARENA_MIN_BYTES)) return 0;

    int const rc = uint64_log2(size_req-1);
    assert_ae(rc, ARENA_MIN_BITS);

    idx_t const idx = 1 + rc - ARENA_MIN_BITS;
    if (unlikely(idx >= NELEM(my_arena()->cache))) {
	return -1;		    /* oversize */
    }

    assert_ae(idx, 1);
    assert_be(idx, ARENA_FREELISTS-1);
    assert_be(size_req, mem_arena_index_size(idx));
    assert_ae(size_req, 1 + mem_arena_index_size(idx-1));

    return idx;
}

buf_t _mem_alloc_oversize(llen_t const size_req, sstring_t const caller_id);
void _mem_free_oversize(mem_hdr_t const, llen_t const, sstring_t const);

/* Allocate a buffer from the appropriately-sized arena cache */
static inline buf_t
_mem_arena_alloc(llen_t const size_req, sstring_t const caller_id)
{
    mem_arena_t const arena = my_arena();
    assert(arena);

    int const idx = _mem_arena_index(size_req);
    if (likely(idx >= 0)) {
	return mem_hdr_to_buf(_mem_cache_alloc(arena->cache[idx], size_req, caller_id));
    } else {
	/* Oversize allocations always come from (and are returned to) the backing allocator */
	return _mem_alloc_oversize(size_req, caller_id);
    }
}

/* Free an allocated buffer (subject to refcounting) --
 * to its originating cache if it has one, or to the backing allocator
 */

static inline void
_mem_free(void const * const buf, llen_t size_req, sstring_t const caller_id)
{
    mem_hdr_t const hdr = mem_hdr_of_buf(buf);
    mem_hdr_check_allocated(hdr);
    if (likely(hdr->cache_owned)) {
	_mem_cache_free(hdr, size_req, caller_id);
    } else {
	/* Return an Oversize allocation to the backing allocator */
	_mem_free_oversize(hdr, size_req, caller_id);
    }
}
 
static inline buf_t
_mem_arena_realloc(buf_t const buf, size_t const newsize, sstring_t const caller_id)
{
    mem_hdr_t const hdr = mem_hdr_of_buf(buf);
    mem_hdr_check_allocated(hdr);
    count_t const inuse = mem_hdr_size_inuse(hdr);

    if (unlikely(newsize == inuse)) {
	/* The new requested size is the same as the current size */
	return buf;
    }

    int oldidx = _mem_arena_index(inuse);	/* bucket index for old size */
    int newidx = _mem_arena_index(newsize);	/* bucket index for new size */

    if (likely(oldidx >= 0 && oldidx == newidx)) {
	/* The new request fits within the existing buffer (including its surplus space) */
	if (newsize > inuse) {
	    memclr(buf + inuse, newsize - inuse);   /* zero the space we extended into */
	} else {
	    memset(buf + newsize, MEM_PATTERN_ALLOC, inuse - newsize); /* zap trimmed space */
	}
	mem_hdr_size_inuse_set(hdr, newsize);	    /* record new size */
	return buf;
    }

    /* Allocate new space and copy from the old */
    return memcpy(mem_alloc_callerid(newsize, caller_id), buf, MIN(inuse, newsize));
}

#endif /* MTE_MEM_IMPL_H */
