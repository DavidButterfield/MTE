/* mte_mem.c
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Fast memory allocator
 */
#define NAME MTE_MEM
#include "mte_util.h"
#include "mte_mem.h"

/* Flags to control memory allocator checking */
bool mem_alloc_pattern_flag = !OPTIMIZED;
bool mem_alloc_redzone_flag = !OPTIMIZED;

int64mt_t mem_hdr_seqno; /* debugging observability -- sequence number for allocs and frees */

/***** Memory allocation header -- keeps refcount, stat, and diagnostic information *****/

void
_mem_buf_allocator_set(void * buf, sstring_t caller_id)
{
    mem_hdr_t const hdr = mem_hdr_of_buf(buf);
    hdr->alloc_caller = caller_id;
}

/* Allocate a NEW aligned buffer and its header FROM THE BACKING ALLOCATOR --
 * the header is initialized to free-state; the buffer itself remains UNinitialized
 */
mem_hdr_t
mem_hdr_alloc(llen_t const buf_size, llen_t const buf_align)
{
    assert(is_power_of_2(buf_align));
    bool const redzone = mem_alloc_redzone_enabled();

    /* Allocate an aligned buffer with an extra align-interval bytes for the header */
    llen_t const total_size = buf_align + mem_buf_size_total(buf_size, buf_align, redzone);
    void * const orig_alloc = mem_hdr_backalloc(total_size, buf_align);

    /* Returned buffer starts one align-interval from the start of the allocation */
    buf_t const buf = orig_alloc + buf_align;

    /* Our header lives just before the returned buffer address */
    mem_hdr_t const hdr = mem_hdr_of_buf(buf);

    /* Initialize our header structure to a good initial free-state */
    record_zero(hdr);
    hdr->magic = MEM_HDR_MAGIC;
    hdr->redzone = redzone;
    mem_hdr_alignment_set(hdr, buf_align);

    /* Write a pattern into the unused memory (if any) just before the header */
    mem_set(orig_alloc, MEM_PATTERN_GAP, buf_align - MEM_HDR_SIZE);

    if (redzone) {
	/* Write a pattern into the redzone after the usable buffer area */
	/* (OK to possibly also write it over the end of the usable buffer area) */
	void * const addr_aligned = (void *)((uintptr_t)(buf + buf_size) & ~0x7);
	mem_set(addr_aligned, MEM_PATTERN_ALLOC, orig_alloc + total_size - addr_aligned);
    }

    mem_hdr_check_free(hdr);	/* ensure our return is in good free-state */
    return hdr;
}

/* Return a header and its buffer TO THE BACKING ALLOCATOR */
void
mem_hdr_free(mem_hdr_t const hdr, sstring_t caller_id)
{
    assert_eq(hdr->magic, MEM_HDR_MAGIC);
    hdr->magic = 0xDEAD;

    llen_t const buf_align = mem_hdr_alignment(hdr);
    llen_t const buf_size = mem_hdr_size_usable(hdr);
    llen_t const total_size =
		    buf_align + mem_buf_size_total(buf_size, buf_align, hdr->redzone);

    buf_t const buf = mem_hdr_to_buf(hdr);
    void * const orig_alloc = buf - buf_align;

    /* Check the pattern in the unused memory (if any) just before the header */
    mem_check_aligned_words(orig_alloc, MEM_PATTERN_GAP, buf_align - MEM_HDR_SIZE);

    mem_hdr_set_freed(hdr, caller_id);

    mem_hdr_backfree(orig_alloc, total_size);
}

#define MEM_HDR_FMT	  "magic=0x%x refs=%u size=%"PRIu64"/%"PRIu64"%s %s=%p %s=%u (%u:%s) %s=%u (%u:%s)"
#define MEM_HDR_FIELDS(h) (h)->magic, \
			  (h)->refcount.i, mem_hdr_size_inuse(h), mem_hdr_size_usable(h), \
			  (h)->size_4k?" 4Kpages":" bytes", \
			  (h)->cache_owned?"cache":"parent", (h)->parent, \
			  (h)->alloc_seqno > (h)->free_seqno ? "A" : "a", \
			  (h)->alloc_seqno, (h)->alloc_tasknum, (h)->alloc_caller, \
			  (h)->alloc_seqno < (h)->free_seqno ? "F" : "f", \
			  (h)->free_seqno, (h)->free_tasknum, (h)->free_caller

/* Return a string describing a memory allocation header */
string_t
mem_hdr_fmt(mem_hdr_t const hdr)
{
    return sys_sprintf(MEM_HDR_FMT, MEM_HDR_FIELDS(hdr));
}

static inline void
_buf_info(buf_t const buf, sstring_t const msg1, sstring_t const msg2)
{
    mem_hdr_t const hdr = mem_hdr_of_buf(buf);
    sys_eprintf("%s %s hdr/buf=%p/%p "MEM_HDR_FMT"\n", msg1, msg2, hdr, hdr+1, MEM_HDR_FIELDS(hdr));
}

/* gdb(1) convenience */
void
buf_info(buf_t const buf)
{
    _buf_info(buf, "", "");
}

/* gdb(1) convenience */
//XXX should lock while traversing MT fifo, but it's only for gdb
void cache_info(mem_cache_t const cache);
void
cache_info(mem_cache_t const cache)
{
    sys_eprintf("Cache name='%s' size=%-6u align=%-4u"
		" nexist=%u nalloc=%"PRIu64"%s "SYS_FREELIST_FMT"\n",
		cache->name, cache->buf_size, cache->buf_align, int32mt_get(&cache->nexist),
		int64mt_get(&cache->nalloc), cache->destructing ? " [destructing]" : "",
		SYS_FREELIST_FIELDS(&cache->freelist));

    sys_link_t * item = cache->mem_hdr_list.head.next;
    while (item) {
	mem_hdr_t const hdr = enclosing_record(item, mem_hdr_t, parent_link);
	buf_info(mem_hdr_to_buf(hdr));
	item = item->next;
    }
}

/* Declare memory corruption detected */
sstring_t NORETURN
mem_hdr_corrupt(mem_hdr_t const hdr, void * buf, sstring_t const info)
{
    sys_error("ERROR: %s -- buf=%p hdr=%p current_mem_hdr_seqno=%"PRIu64,
	      info, buf, hdr, int64mt_get(&mem_hdr_seqno));
    string_t const hdr_str = mem_hdr_fmt(hdr);
    sys_error("buffer: %s", hdr_str);
    sys_panic("memory corruption");
}

/***** Memory freelist cache -- caches one size of free buffers *****/

mem_cache_t
mem_cache_create(sstring_t const name, llen_t const buf_size, llen_t const buf_align)
{
    trace("name='%s' size=%"PRIu64" align=%"PRIu64, name, buf_size, buf_align);
    verify_ae(buf_size, 1);
    verify(is_power_of_2(buf_align), "buf_align=%"PRIu64, buf_align);

    mem_cache_t ret;
    mem_hdr_t const hdr = mem_hdr_alloc(sizeof(*ret), MEM_ALIGN_MIN);
    mem_hdr_set_allocated(hdr, sizeof(*ret), FL_STR);

    ret = mem_hdr_to_buf(hdr);
    record_zero(ret);
    ret->magic = MEMCACHE_MAGIC;
    ret->name = name;
    ret->buf_size = buf_size;
    ret->buf_align = buf_align;
    ret->trace = TRACE_TOOVERBOSE;
    sys_fifo_init(&ret->mem_hdr_list);

    count_t max_items_in_hoard = MAX(1, MIN(8192, 2*MEGA / buf_size));	//XXXX TUNE
    if (buf_size == 4096) max_items_in_hoard = 32000;			//XXXX TUNE

    sys_freelist_init(&ret->freelist, max_items_in_hoard);

    if (ret->buf_align < MEM_ALIGN_MIN) {
	ret->buf_align = MEM_ALIGN_MIN;
    } else if (ret->buf_align > MEM_ALIGN_MAX) {
	sys_warning("limiting excessive alignment %u to %"PRIu64"", ret->buf_align, MEM_ALIGN_MAX);
	ret->buf_align = MEM_ALIGN_MAX;
    }

    mem_cache_check(ret);
    return ret;
}

/* Attempt to destroy a memory cache -- frees its cached free buffers to the backing allocator;
 * if all the cache's allocations have been returned (freed) back to the cache, then the cache
 * itself is also freed.  Otherwise all the buffers currently in the free-cache are freed, but
 * the cache itself remains intact to receive its remaining buffers if/as they become free.
 *
 * Returns true if the cache was entirely freed, in which case the incoming cache pointer is no
 * longer valid; or false if the cache remains intact and the pointer valid.  In the latter
 * case, mem_cache_destroy may be called again at some later time to try again, which may
 * succeed if all the cache's buffers have been returned in the meantime.
 */
bool
mem_cache_destroy(mem_cache_t const cache)
{
    trace_verbose("%s", cache->name);
    mem_cache_check(cache);
    assert(!cache->destructing);
    cache->destructing = true;

    int64_t mem_hdr_seqno_snapshot = int64mt_get(&mem_hdr_seqno);

    /* First take everything from the freelist and mark it for destruction */
    count_t ndestructing = 0;
    idx_t hoardnum;
    for (hoardnum = 0; hoardnum < cache->freelist.nhoard; hoardnum++) {
	mem_hdr_t hdr;
	while ((hdr = sys_freelist_hoard_take_entry(
				&cache->freelist, hoardnum, mem_hdr_t, free_link))) {
	    assert_eq(int32mt_get(&hdr->refcount), 0);
	    hdr->destructing = true;
	    ++ndestructing;
	}
    }

    /* Now go down the full list, freeing what we marked and keeping what we didn't */
    sys_fifo_t unfreed;		/* temp hold for the one's we're keeping */
    sys_fifo_init(&unfreed);

    mem_hdr_t hdr;
    count_t ndestructed = 0;
    while ((hdr = sys_fifo_take_entry(&cache->mem_hdr_list, mem_hdr_t, parent_link))) {
	if (hdr->destructing) {
	    /* We marked this allocation to be freed -- free it */
	    assert_eq(int32mt_get(&hdr->refcount), 0);
	    mem_hdr_free(hdr, FL_STR);
	    ++ndestructed;
	    int32mt_dec(&cache->nexist);
	} else {
	    /* This allocation was not in the free state -- keep it */
	    sys_fifo_append(&unfreed, &hdr->parent_link);
	    _buf_info(mem_hdr_to_buf(hdr), cache->name, "UNFREED: ");
	}
    }

    assert_eq(ndestructing, ndestructed);

    /* See if we have any unfreed buffers */
    if (sys_fifo_nitem(&unfreed) > 0 || int32mt_get(&cache->nexist)) {
	/* Not all the buffers owned by this cache have been freed */
	sys_warning("mem_cache_destroy(%p, %s size=%u) returns false"
	      " (nfreed=%u nunfreed=%u nexist=%u mem_hdr_seqno=%"PRIu64")",
	      cache, cache->name, cache->buf_size, ndestructed,
	      sys_fifo_nitem(&unfreed), int32mt_get(&cache->nexist),
	      mem_hdr_seqno_snapshot);

	/* Put the unfreed buffers back onto the cache's mem_hdr_list */
	sys_fifo_xfer(&cache->mem_hdr_list, &unfreed);
	sys_fifo_deinit(&unfreed);
	cache->destructing = false;
	return false;		/* Unable to free the entire cache */
    }

    if (cache->trace || trace_is_enabled()) {
	if (ndestructed) {
	    trace("mem_cache_destroy(%p, %s size=%u) returns true (nfreed=%u)",
		  cache, cache->name, cache->buf_size, ndestructed);
	}
    }

    sys_fifo_deinit(&unfreed);	/* done with this */

    /* All the cache's buffers have been freed -- free the cache */
    sys_freelist_deinit(&cache->freelist);
    sys_fifo_deinit(&cache->mem_hdr_list);

    mem_hdr_free(mem_hdr_of_buf(cache), FL_STR);    /* free the cache structure itself */

    return true;		/* Freed the cache and all its buffers */
}

string_t
mem_cache_fmt(mem_cache_t const cache)
{
    return sys_sprintf("name='%s' size=%-6u align=%-4u nalloc=%-8"PRIu64" nexist=%-6u "
		       SYS_FREELIST_FMT,
		       cache->name, cache->buf_size, cache->buf_align,
		       cache->nalloc.i, cache->nexist.i,
		       SYS_FREELIST_FIELDS(&cache->freelist));
}

/***** Memory cache arena -- keeps mem_caches of various sizes *****/

/* Oversize allocations always come from (and are returned to) the backing allocator */
buf_t
_mem_alloc_oversize(llen_t const size_req, sstring_t const caller_id)
{
    assert_ae(size_req, 1 + ARENA_MAX_BYTES);

    mem_arena_t const arena = my_arena();
    int32mt_inc(&arena->oversize.nallocs);

    if (trace_verbose_is_enabled()) sys_backtrace("oversize memory allocation");

    mem_hdr_t const hdr = mem_hdr_alloc(size_req, MEM_ALIGN_MAX);
    hdr->cache_owned = false;
    mem_hdr_set_allocated(hdr, size_req, caller_id);

#if !OPTIMIZED	    /* oversize allocation logging */
    sys_notice("OVERSIZE memory allocation: hdr=%p size_req=%"PRIu64" arena=%p -- %s",
	       hdr, size_req, arena, caller_id);
#endif

    return mem_hdr_to_buf(hdr);
}

/* Return an Oversize allocation to the backing allocator */
void
_mem_free_oversize(mem_hdr_t const hdr, llen_t const size_req, sstring_t const caller_id)
{
    assert_eq(mem_hdr_size_inuse(hdr), size_req);

    bool const last_ref = mem_hdr_refdrop(hdr, caller_id);
    if (last_ref) {
#if !OPTIMIZED	    /* oversize allocation logging */
	sys_notice("Oversize hdr=%p size_req=%"PRIu64" refs=%u -- %s",
		   hdr, size_req, hdr->refcount.i, caller_id);
#endif
	mem_hdr_free(hdr, caller_id);
	mem_arena_t const arena = my_arena();
	assert(arena);
	int32mt_inc(&arena->oversize.nfrees);
#if !OPTIMIZED	    /* oversize allocation logging */
    } else {
	trace_verbose("Oversize hdr=%p size_req=%"PRIu64" now refs=%u -- %s",
		      hdr, size_req, hdr->refcount.i, caller_id);
#endif
    }
}

static inline len_t
mem_alloc_align_default(len_t const size)
{
    if (size < MEM_ALIGN_SECTOR) return MEM_ALIGN_MIN;
    if (size < MEM_ALIGN_MAX) return MEM_ALIGN_SECTOR;
    return MEM_ALIGN_MAX;
}

mem_arena_t
mem_arena_create(sstring_t const name)
{
    trace_verbose();
    mem_arena_t arena;
    mem_hdr_t const hdr = mem_hdr_alloc(sizeof(*arena), MEM_ALIGN_MIN);
    mem_hdr_set_allocated(hdr, sizeof(*arena), FL_STR);

    arena = mem_hdr_to_buf(hdr);
    record_zero(arena);
    arena->magic = MEM_ARENA_MAGIC;

    idx_t i;
    for (i = 0; i < NELEM(arena->cache); i++) {
	len_t const size = mem_arena_index_size(i);
	len_t const align = mem_alloc_align_default(size);
	arena->cache[i] = mem_cache_create(name, size, align);
    }

    mem_arena_check(arena);
    return arena;
}

errno_t
mem_arena_destroy(mem_arena_t const arena)
{
    trace_verbose();
    mem_arena_check(arena);

    uint64_t const seqno = int64mt_get(&mem_hdr_seqno);
    bool ok = true;

    idx_t i;
    for (i = 0; i < NELEM(arena->cache); i++) {
	if (!arena->cache[i]) continue;
	if (mem_cache_destroy(arena->cache[i])) {
	    arena->cache[i] = NULL;
	} else {
	    ok = false;
	}
    }

    if (arena->oversize.nfrees.i != arena->oversize.nallocs.i) {
	sys_warning("oversize.nfrees (%u) != (%u) oversize.nallocs",
		      arena->oversize.nfrees.i, arena->oversize.nallocs.i);
	ok = false;
    }

    if (ok) {
	mem_hdr_free(mem_hdr_of_buf(arena), FL_STR);	/* free the arena structure itself */
	sys_notice("Successfully destroyed arena\n");
	return E_OK;
    }

    sys_warning("Failed to destroy arena, mem_hdr_seqno=%"PRIu64, seqno);
    return EBUSY;
}

string_t
mem_arena_fmt(mem_arena_t const arena)
{
    string_t ret = string_empty();

    idx_t i;
    for (i = 0; i < NELEM(arena->cache); i++) {
	mem_cache_t const cache = arena->cache[i];
	assert(cache);
	if (int64mt_get(&cache->nalloc) == 0) continue;
	ret = string_concat_free(ret, mem_cache_fmt(cache));
	ret = sys_sprintf_append(ret, "\n");
    }

    if (int32mt_get(&arena->oversize.nallocs) == 0) return ret;

    count_t const nopen = int32mt_get(&arena->oversize.nallocs) -
						int32mt_get(&arena->oversize.nfrees);
    ret = sys_sprintf_append(ret,
	    "[%u]                   OVERSIZE   align=%4u allocs=%-9u frees=%-9u open=%-9u",
	    sys_thread_num(sys_thread), (uint32_t)MEM_ALIGN_MAX,
	    int32mt_get(&arena->oversize.nallocs), int32mt_get(&arena->oversize.nfrees), nopen);

    return ret;
}

void mem_arena_dump(void);
void
mem_arena_dump(void)
{
    string_t stat_str = mem_stats();
    write(2, stat_str, strlen(stat_str));
    string_free(stat_str);
}

#if !ARENA_DISABLE

/*****  Memory concatination  *****
 * Concatination helper called by wrappers below after computing desired lengths --
 *
 * Return a memory buffer holding the concatination of the first prefix_len bytes of prefix_buf
 * with the first suffix_len bytes of suffix_buf.  prefix_buf and suffix_buf must be buffer
 * addresses previously returned from the memory allocator.
 *
 * The interface model is that BOTH of the two argument memory buffers are CONSUMED and a NEW
 * buffer is RETURNED with their concatinated contents (up to their respective length arguments)
 *
 * The implementation attempts to fit the concatination into either one of the input memory
 * buffers, so as to avoid an alloc/free pair; it also avoids copying the prefix bytes, in
 * cases where the *prefix* buffer is large enough to hold the concatination.
 */
static buf_t
__mem_concat_free(buf_t const prefix_buf, llen_t const prefix_len,
	          buf_t const suffix_buf, llen_t const suffix_len, sstring_t const caller_id)
{
    assert(prefix_buf);
    mem_hdr_t const prefix_hdr = mem_hdr_of_buf(prefix_buf);
    assert_be(prefix_len, mem_hdr_size_inuse(prefix_hdr));
    llen_t const prefix_avail = mem_hdr_size_usable(prefix_hdr) - prefix_len;

    assert(suffix_buf);
    mem_hdr_t const suffix_hdr = mem_hdr_of_buf(suffix_buf);
    assert_be(suffix_len, mem_hdr_size_inuse(suffix_hdr));
    llen_t const suffix_avail = mem_hdr_size_usable(suffix_hdr) - suffix_len;

    if (prefix_avail >= suffix_len) {
	/* The concatination will fit in the existing prefix buffer */
	/* Copy the suffix into the prefix buffer just after the prefix */
	memcpy(prefix_buf + prefix_len, suffix_buf, suffix_len);
	mem_hdr_size_inuse_set(prefix_hdr, prefix_len + suffix_len);
	mem_drop_callerid(suffix_buf, caller_id);	/* free the suffix buf */
	return prefix_buf;
    } else if (suffix_avail >= prefix_len) {
	/* The concatination will fit in the existing suffix buffer */
	/* Make space at the start of the suffix for the prefix */
	memmove(suffix_buf + prefix_len, suffix_buf, suffix_len);
	/* Copy the prefix into the beginning of the suffix buffer */
	memcpy(suffix_buf, prefix_buf, prefix_len);
	mem_hdr_size_inuse_set(suffix_hdr, prefix_len + suffix_len);
	mem_drop_callerid(prefix_buf, caller_id);	/* free the prefix buf */
	return suffix_buf;
    } else {
	/* The concatination will not fit in either existing input buffer */
	/* Allocate a new (larger) buffer for the concatination */
	char * const new_buf = mem_alloc_uninit_callerid(prefix_len + suffix_len, caller_id);
	/* Copy the prefix and suffix strings into the new buffer */
	memcpy(new_buf, prefix_buf, prefix_len);
	memcpy(new_buf + prefix_len, suffix_buf, suffix_len);
	mem_drop_callerid(prefix_buf, caller_id);	/* free the prefix buf */
	mem_drop_callerid(suffix_buf, caller_id);	/* free the suffix buf */
	return new_buf;
    }
}

/* Return a memory buffer holding the concatination of the size_inuse content of prefix_buf and
 * suffix_buf, each of which must be either NULL or a buffer address returned from the memory
 * allocator; if both are NULL, NULL is returned.
 */
buf_t
_mem_concat_free(buf_t const prefix_buf, buf_t const suffix_buf, sstring_t const caller_id)
{
    if (!prefix_buf) return suffix_buf;
    if (!suffix_buf) return prefix_buf;

    mem_hdr_t const prefix_hdr = mem_hdr_of_buf(prefix_buf);
    assert(!prefix_hdr->size_4k);
    count_t const prefix_inuse = mem_hdr_size_inuse(prefix_hdr);

    mem_hdr_t const suffix_hdr = mem_hdr_of_buf(suffix_buf);
    assert(!suffix_hdr->size_4k);
    count_t const suffix_inuse = mem_hdr_size_inuse(suffix_hdr);

    return __mem_concat_free(prefix_buf, prefix_inuse, suffix_buf, suffix_inuse, caller_id);
}

/***** Efficient string concatination  *****
 *
 * Append suffix string to prefix string, CONSUMING BOTH and returning the concatination --
 * either or both strings may be NULL -- if both, NULL is returned.
 */
string_t
mem_string_concat_free(string_t prefix_str, string_t suffix_str, sstring_t caller_id)
{
    if (!prefix_str) return suffix_str;
    if (!suffix_str) return prefix_str;

    buf_t const prefix_buf = unconstify(prefix_str);
    mem_hdr_t const prefix_hdr = mem_hdr_of_buf(prefix_buf);
    assert(!prefix_hdr->size_4k);	    /* want byte precision */
    llen_t const prefix_inuse = mem_hdr_size_inuse(prefix_hdr);
    assert_eq(prefix_inuse, strlen(prefix_str) + 1/*nul*/);

    buf_t const suffix_buf = unconstify(suffix_str);
    mem_hdr_t const suffix_hdr = mem_hdr_of_buf(suffix_buf);
    assert(!suffix_hdr->size_4k);	    /* want byte precision */
    llen_t const suffix_inuse = mem_hdr_size_inuse(suffix_hdr);
    assert_eq(suffix_inuse, strlen(suffix_str) + 1/*nul*/);

    return __mem_concat_free(prefix_buf, prefix_inuse - 1/*nul*/,
			     suffix_buf, suffix_inuse, caller_id);
}

#else

string_t
mem_string_concat_free(string_t prefix_str, string_t suffix_str, sstring_t caller_id)
{
    if (!prefix_str) return suffix_str;
    if (!suffix_str) return prefix_str;
    count_t const prefix_len = strlen(prefix_str);
    count_t const suffix_len = strlen(suffix_str);
    char * const ret = mem_alloc(prefix_len + suffix_len + 1);
    memcpy(ret, prefix_str, prefix_len);
    memcpy(ret+prefix_len, suffix_str, suffix_len);
    assert_eq(ret[prefix_len+suffix_len], '\0');
    mem_drop(prefix_str);
    mem_drop(suffix_str);
    return ret;
}

#endif

void
mem_init(void)
{
    assert_eq(MEM_HDR_SIZE % 8, 0);		/* structure must be size-aligned at least 8 */
    assert_be(MEM_HDR_SIZE, MEM_ALIGN_MIN);	/* header must fit in one MIN_ALIGN */
    assert_eq(MEM_HDR_SIZE, MEM_ALIGN_MIN);	/* let's go with this assumption for now */

}
