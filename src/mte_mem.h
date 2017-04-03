/* mte_mem.h
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Fast memory allocator provides per-thread free-buffer caching to outperform malloc.
 */
#include "mte_util.h"
#ifndef MTE_MEM_H
#define MTE_MEM_H
#include <string.h>

void mem_init(void);

/* Memory allocator overview:
 *
 * XXX FIX COMMENT -- way out of date!
 * A PER_THREAD general memory allocation arena maintains an array of free-buffer caches of a
 * few standardized sizes (selected powers of two), from which to satisfy allocation requests.
 *
 * Summary of memory allocator layers (all compilable together inline) --
 *
 *   mem_alloc, record_alloc, array_alloc
 *	    main public interfaces to memory allocator, return buffers CLEARED TO ZERO
 *	    mem_alloc_uninit omits zeroing the buffer
 *
 *   mem_arena_t (instance per-thread, private to memory allocator)
 *	    free-cache for general allocation handles multiple mem_cache_t of various size
 *	    buffers; implements oversize allocations directly with mem_hdr_t
 *
 *   mem_cache_t (public interface to one-size memory cache)
 *	    caches free buffers of a single (maximum usable) size; used by the mem_arena
 *	    for general allocation; also usable directly in the style of kmem_cache_alloc
 *
 *   mem_hdr_t (quasi-private to memory allocator)
 *	    maintains information header before each allocated buffer and cached freed buffer,
 *	    much of which is debugging and check information.  This layer also writes and checks
 *	    patterns (when enabled) in memory that should be idle.  Notable additional features:
 *	      > there is special support for improving the efficiency of string_append;
 *	      > every buffer is reference-counted; the allocating caller starts with one ref;
 *	        a reference holder can take additional holds; a hold can be passed cross-thread;
 *	        buffers are freeable from any thread;
 *
 *   posix_alloc, posix_alloc_aligned (quasi-private to memory allocator)
 *	    primordial allocator, allocates aligned memory using POSIX C library calls.
 */

/* define true if allocations larger than 4GB are needed; more efficient when false */
#define MEM_ALLOC_HUGE	false

/* These definitions bind (at compile-time) memory allocation requests (coming from clients of
 * the memory allocation layer) to some memory allocator implementation.  Doing it this way
 * allows frequent code paths for memory allocation and free to be fully inlined, while still
 * retaining relative ease of compile-time substitution of the underlying implementation here.
 *
 * XXX FIX COMMENT
 * Most macros defined here make buffer allocations implicitly from the calling thread's general
 * allocation arena.  When freed, a buffer to be retained in a freelist cache (not oversize)
 * is returned to a freelist in the ORIGINATING arena -- which is NOT necessarily the current
 * thread's arena:  if ownership of the buffer has been passed from the allocating thread to
 * some other thread, the buffer may be freed from the second thread.  (It may be instructive
 * to consider why the freeing buffer is sent back to its originating arena, rather than being
 * retained on a freelist in the freeing thread's arena.)
 *
 * Each allocated buffer has built-in support for MT-safe reference counting.  The allocator
 * of a buffer starts out with one reference "hold" on the buffer.  Ownership of that hold on
 * the buffer may be passed around from thread to thread by application-specific protocol.
 * A current owner of a hold can take additional holds and pass ownership of them to other
 * threads (and transitively).  The buffer recycles back to the originating arena's freelist
 * when any additional hold(s) applied, and the hold from the initial allocation, have each
 * been matched by a free (or mem_drop).
 */
#ifndef ARENA_DISABLE
#define ARENA_DISABLE false
#endif
#if ARENA_DISABLE		/* Only true for special testing */
				/* (in which case mem_hold isn't quite right) */
#define mem_alloc(size_req)			mem_zero(mem_alloc_uninit(size_req), (size_req))
#define mem_alloc_callerid(size_req, id)	mem_zero(mem_alloc_uninit(size_req), (size_req))
#define mem_alloc_uninit(size_req)		posix_alloc(size_req)
#define mem_alloc_uninit_callerid(size_req, id)	posix_alloc(size_req)
#define mem_free(buf, size_req)			posix_free((buf), (size_req))
#define mem_free_callerid(buf, size_req, id)	posix_free((buf), (size_req))
#define mem_drop(buf)				posix_drop(buf)
#define mem_drop_callerid(buf, id)		posix_drop(buf)
#define mem_hold(buf, ofs, len)			({ \
	    buf_t const _newbuf = mem_alloc_uninit((ofs)+(len)); \
	    memcpy(_newbuf, (buf), (ofs)+(len)); \
	    _newbuf; \
	})
#define mem_check(buf)				do { } while (0)
#define mem_fmt(buf)				do { } while (0)
#define mem_stats()				sstring_copy("No mem_stats with ARENA_DISABLE")
#define mem_bounds_check(buf, ofs, nbytes)	do { } while (0)
#define mem_cache_alloc_uninit(cache)		mem_alloc_uninit((cache)->buf_size)
#define mem_buf_allocator_set(buf, whence)	do { } while (0)
#else

// XXX FIX COMMENT
/* Allocate (size_req) bytes of CLEARED space (all bytes set to zero) from the current thread's
 * general allocation arena.  The returned buffer pointer will point to a cleared area of
 * memory of length (size_req), which is followed by an adjacent SURPLUS area of ZERO or more
 * bytes (filled with a diagnostic pattern, if enabled).  The MEM_HDR_SIZE bytes immediately
 * PRECEDING the returned pointer will contain the mem_hdr_t associated with the buffer.
 * Depending on alignment there may be a GAP of unused memory before the start of the header.
 */
#define mem_alloc(size_req) ASSUME_ALIGNED( \
	    mem_zero_startaligned(mem_alloc_uninit(size_req), size_req), MEM_ALIGN_MIN)
#define mem_alloc_callerid(size_req, callerid) ASSUME_ALIGNED( \
	    mem_zero_startaligned(mem_alloc_uninit_callerid((size_req), (callerid)), size_req),\
							      MEM_ALIGN_MIN)

#define mem_realloc_callerid(oaddr, nsize, whence) \
	    ASSUME_ALIGNED( _mem_arena_realloc((oaddr), (nsize), (whence)), MEM_ALIGN_MIN)

/* To get uninitialized memory you must ask for it explicitly */
#define mem_alloc_uninit(size_req) ASSUME_ALIGNED( \
	    _mem_arena_alloc((size_req), FL_STR), MEM_ALIGN_MIN)

#define mem_alloc_uninit_callerid(size_req, callerid) ASSUME_ALIGNED( \
	    _mem_arena_alloc((size_req), (callerid)), MEM_ALIGN_MIN)

/* Free (size_req) bytes of memory starting at buf -- buf must be a pointer to a buffer returned
 * previously from mem_alloc (or family); size_bytes is for checking and must match the size
 * specified when the buffer was allocated.
 *
 * To "free" a buffer means to release one hold on it -- a buffer starts out with one hold when
 * allocated, and additional holds can be applied using mem_hold(buf).  When a call to free a
 * buffer decreases the number of holds to zero, the buffer is recycled onto a freelist (or
 * returned to the backing allocator in the case of oversize allocations, which aren't cached).
 */
#define mem_free(buf, size_req)			_mem_free((buf), (size_req), FL_STR)
#define mem_free_callerid(buf, size_req, id)	_mem_free((buf), (size_req), (id))

/* These operate on any buffer allocated with a mem_hdr_t (no cache needed, e.g. oversize) */
#define mem_hold(buf)			buf_hold((buf), 0, mem_buf_size_inuse(buf))
#define buf_hold(buf, ofs, len)		ASSUME_ALIGNED( \
					    mem_hdr_refhold(mem_hdr_of_buf(buf), FL_STR), \
					    MEM_ALIGN_MIN)
#define mem_drop(buf)			mem_free((buf), mem_buf_size_inuse(buf))
#define mem_drop_callerid(buf, id)	mem_free_callerid((buf), mem_buf_size_inuse(buf),(id))

#define mem_check(buf)			mem_hdr_check_allocated(mem_hdr_of_buf(buf))
#define mem_fmt(buf)			mem_hdr_fmt(mem_hdr_of_buf(buf))

/* Return a status/stats string for the general allocation arena */
#define mem_stats()			mem_arena_fmt(sys_mem_arena)

#define mem_bounds_check(buf, ofs, nbytes) \
	    do { \
		mem_check(buf); \
		assert_be(ofs + nbytes, mem_buf_size_inuse(buf), \
			  "buf=%p ofs=%u nbytes=%u size=%"U64, \
			   (buf), (ofs), (len_t)(nbytes), mem_buf_size_inuse(buf)); \
	    } while (0)

#define mem_cache_alloc_uninit(cache) ASSUME_ALIGNED( \
		mem_hdr_to_buf(_mem_cache_alloc((cache), (cache)->buf_size, FL_STR)), \
	        MEM_ALIGN_MIN)

#define mem_buf_allocator_set(buf, whence)  _mem_buf_allocator_set((buf), (whence))	

#endif

/* These definitions are generic, not bindings to any particular allocator implementation */

/* Allocate from (free to) a custom memory free-buffer cache (outside of main arena) --
 * An individual CACHE manages only one size of buffer.  Two main uses are:
 *
 * XXX FIX COMMENT -- way out of date!
 *    A memory freecache ARENA uses an array of these CACHES with various buffer sizes to
 *    implement a general PER_THREAD memory allocation cache, where an allocation request
 *    of a given size is filled from whichever cache in the current thread's arena is
 *    configured with the smallest buffers of sufficient size to satisfy the request.
 *
 *    Memory free-buffer caches may also be individually allocated and used as memory
 *    caches of custom sizes using these macros:
 */
#define mem_cache_alloc(cache) ASSUME_ALIGNED( \
	    mem_zero_startaligned(mem_cache_alloc_uninit(cache), (cache)->buf_size), \
	    MEM_ALIGN_MIN)

typedef void * buf_t;

/* create or destroy one memory cache, or format its stats */
typedef struct mem_cache  * mem_cache_t;
mem_cache_t		    mem_cache_create(sstring_t name, llen_t buf_size, llen_t buf_align);
bool			    mem_cache_destroy(mem_cache_t cache);
string_t		    mem_cache_fmt(mem_cache_t cache);

/* Clear a section of memory to zero */
#define memclr(ptr, size_req)		mem_zero((ptr), (size_req))

/* "Zap" a section of memory by setting it to contain a pattern (omit when OPTIMIZED) */
#define mem_zap(addr, len)  (void)(OPTIMIZED ? (addr) : mem_set((addr), MEM_ZAP, (len)))
#define record_zap(ptr_var) mem_zap((ptr_var), sizeof(*(ptr_var)))

/* Concatinate prefix and suffix buffers, CONSUMING BOTH and returning the concatination --
 * either or both buffer pointers may be NULL -- if both, NULL is returned.
 */
#define mem_concat_free(prefix, suffix) _mem_concat_free((prefix), (suffix), FL_STR)
buf_t _mem_concat_free(buf_t const prefix, buf_t const suffix, sstring_t const caller_id);

/* Allocate space and make a new copy of the specified buffer */
#define buf_copy(buf)			sys_mem_dup((buf), mem_buf_size_inuse(buf))

/* Allocate space and make a new copy of the specified string / free a string */
#define string_copy(str)		(buf_copy(str))	/* must be one of our allocations */
#define string_is_empty(str)		(string_check(str), *(char *)str == '\0')
#define string_empty(str)		mem_alloc(1)
#define string_length(str)		(str ? strlen(str) : 0)
					/* must be one of our allocations XXXX TUNE optmize */

#if ARENA_DISABLE
  #define string_check(str) (void)({ true; })
#elif DEBUG	/* string_check compares string length with its mem_buf_size_inuse */
  #define string_check(str) (void)({ \
				    mem_check(str); \
				    count_t const _len_total = mem_buf_size_inuse(str); \
				    count_t const _len_string = strnlen((str), _len_total); \
				    assert_eq(_len_string, _len_total-1); \
				    true; \
			          })
#else
  #define string_check(str) (void)({ mem_check(str); true; })
#endif

/* Append suffix string to prefix string, CONSUMING BOTH and returning the concatination --
 * either or both strings may be NULL -- if both, NULL is returned.
 */
#define string_concat_free(prefix, suffix) mem_string_concat_free((prefix), (suffix), FL_STR)
string_t mem_string_concat_free(string_t const prefix, string_t const suffix,
							sstring_t const caller_id);

#include "mte_mem_impl.h"   /* implementation-private inline functions */

#endif /* MTE_MEM_H */
