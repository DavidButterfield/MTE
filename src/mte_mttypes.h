/* sys_mttypes.h
 * Copyright 2015 David A. Butterfield
 * High-Performance Multithreaded Event Engine
 *
 * Multi-thread safe types --
 * None of the functions in this file block (give up the CPU)
 * (however sys_spin_lock and the CAS functions may spin).
 */
#ifndef SYS_MTTYPES_H
#define SYS_MTTYPES_H
#include <sched.h>

#include "mte_defines.h"
#include "mte_debug.h"

#ifndef TRACE_STATS
#define TRACE_STATS true
#endif

#ifndef SYS_LOCK_STATS
#define SYS_LOCK_STATS true
#endif

#ifndef SYS_LOCK_CHECKS
#define SYS_LOCK_CHECKS true
#endif

/* Issue a full memory barrier */
#define sys_membar()	__sync_synchronize()

/* For inclusion in spin-wait loops to improve CPU behavior */
#ifdef NVALGRIND
  extern bool _MTE_gcc_junk;	/* avoid gcc warning */
  #define SYS_SPINWAITING()	(__builtin_ia32_pause(), _MTE_gcc_junk = true)
#else
  //XXX F3 90 CPU spinloop hint seems to confuse valgrind (though possibly it's exposing a race)

  //XXX CPU spinloop hint under valgrind apparently intermittently results in a valgrind loop/hang
  // #define SYS_SPINWAITING()	(__builtin_ia32_pause(), true)

  //XXX Merely asking if valgrind_is_active in the loop seems to hang also...
  // #define SYS_SPINWAITING() (valgrind_is_active() ? ({do{}while(0);true;}) : (__builtin_ia32_pause(), true))
  // #define SYS_SPINWAITING()	(valgrind_is_active() ? true : true)

  // This works for valgrind, but isn't optimal for performance
  #define SYS_SPINWAITING()	({ do {} while (0); true; })
#endif

/*** One-byte MT-safe lock with barriers (holds one bit of information) ***/
/*   See also sys_spinlock_t which adds ownership checking capability     */

typedef struct {
    uint8_t volatile lock;
} sys_lock_t;

#define SYS_LOCK_INIT()		{ .lock = 0 }

static always_inline void
sys_lock_init(sys_lock_t * const lock)
{
    *lock = (sys_lock_t)SYS_LOCK_INIT();
}

/* Release a lock previously acquired, and issue a release barrier */
static always_inline void
sys_lock_release(sys_lock_t * const lock)
{
    __sync_lock_release(&lock->lock);
}

/* Attempt to acquire a (one-bit test-and-set) lock, and issue an acquire barrier --
 * Returns true if lock is acquired, false if lock was already being held by some thread
 */
static always_inline bool
sys_lock_acquire_try(sys_lock_t * const lock)
{
    uint8_t const previous = __sync_lock_test_and_set(&lock->lock, 1);
    return previous == 0;
}

/* Acquire a (one-bit test-and-set) lock, and issue an acquire barrier --
 * Spins if necessary until the lock is available.
 */
#define sys_lock_acquire_spin(lock) \
	    do { } while (!sys_lock_acquire_try(lock) && SYS_SPINWAITING())

/******************************************************************************/

/***** MT-safe non-blocking 64-bit integer with full barrier (int64mt_t) *****/

typedef struct {
    int64_t volatile i;
} int64mt_t;

/*** Arithmetic operators return the NEW value ***/

/* Atomic ADD of value into mt64 -- returns the NEW value */
static always_inline int64_t
int64mt_add(int64mt_t * const mt64, int64_t const value)
{
    return __sync_add_and_fetch(&mt64->i, value);
}

/* Atomic SUB of value from mt64 -- returns the NEW value */
static always_inline int64_t
int64mt_sub(int64mt_t * const mt64, int64_t const value)
{
    return __sync_sub_and_fetch(&mt64->i, value);
}

/* Atomic increment of mt64 -- returns the NEW value */
static always_inline int64_t
int64mt_inc(int64mt_t * const mt64)
{
    return int64mt_add(mt64, 1);
}

/* Atomic decrement of mt64 -- returns the NEW value */
static always_inline int64_t
int64mt_dec(int64mt_t * const mt64)
{
    return int64mt_sub(mt64, 1);
}

/*** Bitwise operators return the OLD value ***/

/* Atomic AND of value into mt64 -- returns the OLD value */
static always_inline int64_t
int64mt_and(int64mt_t * const mt64, int64_t const value)
{
    return __sync_fetch_and_and(&mt64->i, value);
}

/* Atomic OR of value into mt64 -- returns the OLD value */
static always_inline int64_t
int64mt_or(int64mt_t * const mt64, int64_t const value)
{
    return __sync_fetch_and_or(&mt64->i, value);
}

/* Atomic XOR of value into mt64 -- returns the OLD value */
static always_inline int64_t
int64mt_xor(int64mt_t * const mt64, int64_t const value)
{
    return __sync_fetch_and_xor(&mt64->i, value);
}

/* Clear mt64 (to zero) -- returns the OLD value */
static always_inline int64_t
int64mt_clr(int64mt_t * const mt64)
{
    return __sync_fetch_and_and(&mt64->i, 0);
}

/* Atomic exchange -- set mt64 to new_val and return the OLD value */
static always_inline int64_t
int64mt_set(int64mt_t * const mt64, int64_t const new_val)
{
    int64_t ret;
    __atomic_exchange(mt64, &new_val, &ret, __ATOMIC_SEQ_CST);
    return ret;
}

/* Fetch and return the current value without changing it */
static always_inline int64_t
int64mt_get(int64mt_t * const mt64)
{
    /* return int64mt_or(mt64, 0); */
    sys_membar();
    return mt64->i;
}

/* Atomic CAS of value with (*int64) --
 * returns true on success, or false if (*int64 != expected)
 */
static always_inline bool
_int64_cas(int64_t volatile * const int64, int64_t const expected, int64_t const newval)
{
    return __sync_bool_compare_and_swap(int64, expected, newval);
}

/* Atomic high-watermark -- returns the (possibly new) high-watermark */
/*				    ~ return *mt64 = max(*mt64, value);   */
static always_inline int64_t
int64mt_hiwat(int64mt_t * const mt64, int64_t const value)
{
    int64_t prev_hiwat;
    do {
	prev_hiwat = mt64->i;
	if (likely(value <= prev_hiwat)) break;
    } while (!_int64_cas(&mt64->i, prev_hiwat, value) && SYS_SPINWAITING());

    return mt64->i;
}

/*** MT-safe non-blocking 32-bit integer with full barrier (int32mt_t) ***/

typedef struct {
    int32_t volatile i;
} int32mt_t;

/** Arithmetic operators return the NEW value **/

/* Atomic ADD of value into mt32 -- returns the NEW value */
static always_inline int32_t
int32mt_add(int32mt_t * const mt32, int32_t const value)
{
    return __sync_add_and_fetch(&mt32->i, value);
}

/* Atomic SUB of value from mt32 -- returns the NEW value */
static always_inline int32_t
int32mt_sub(int32mt_t * const mt32, int32_t const value)
{
    return __sync_sub_and_fetch(&mt32->i, value);
}

/* Atomic increment of mt32 -- returns the NEW value */
static always_inline int32_t
int32mt_inc(int32mt_t * const mt32)
{
    return int32mt_add(mt32, 1);
}

/* Atomic decrement of mt32 -- returns the NEW value */
static always_inline int32_t
int32mt_dec(int32mt_t * const mt32)
{
    return int32mt_sub(mt32, 1);
}

/** Bitwise operators return the OLD value **/

/* Atomic AND of value into mt32 -- returns the OLD value */
static always_inline int32_t
int32mt_and(int32mt_t * const mt32, int32_t const value)
{
    return __sync_fetch_and_and(&mt32->i, value);
}

/* Atomic OR of value into mt32 -- returns the OLD value */
static always_inline int32_t
int32mt_or(int32mt_t * const mt32, int32_t const value)
{
    return __sync_fetch_and_or(&mt32->i, value);
}

/* Atomic XOR of value into mt32 -- returns the OLD value */
static always_inline int32_t
int32mt_xor(int32mt_t * const mt32, int32_t const value)
{
    return __sync_fetch_and_xor(&mt32->i, value);
}

/* Clear mt32 (to zero) -- returns the OLD value */
static always_inline int32_t
int32mt_clr(int32mt_t * const mt32)
{
    return __sync_fetch_and_and(&mt32->i, 0);
}

/* Atomic exchange -- set mt32 to new_val and return the OLD value */
static always_inline int32_t
int32mt_set(int32mt_t * const mt32, int32_t const new_val)
{
    int32_t ret;
    __atomic_exchange(mt32, &new_val, &ret, __ATOMIC_SEQ_CST);
    return ret;
}

/* Fetch and return the current value without changing it */
static always_inline int32_t
int32mt_get(int32mt_t * const mt32)
{
    /* return int32mt_or(mt32, 0); */
    sys_membar();
    return mt32->i;
}

/* Atomic CAS of value with (*int32) --
 * returns true on success, or false if (*int32 != expected)
 */
static always_inline bool
_int32_cas(int32_t volatile * const int32, int32_t const expected, int32_t const newval)
{
    return __sync_bool_compare_and_swap(int32, expected, newval);
}

/* Atomic high-watermark -- returns the (possibly new) high-watermark */
/*				    return *mt32 = max(*mt32, value);   */
static always_inline int32_t
int32mt_hiwat(int32mt_t * const mt32, int32_t const value)
{
    int32_t prev_hiwat;
    do {
	prev_hiwat = mt32->i;
	if (likely(value <= prev_hiwat)) break;
    } while (!_int32_cas(&mt32->i, prev_hiwat, value) && SYS_SPINWAITING());

    return mt32->i;
}

/******************************************************************************/

/*** sys_spinlock enhances sys_lock with stats and owner in DEBUG builds for observability ***/

typedef struct {
    sys_lock_t		    lockbit;
#if SYS_LOCK_CHECKS
    sys_thread_t   volatile owner;
#endif
#if SYS_LOCK_STATS    /* sys_spinlock owner and stats */
    uint64_t		    nlock;	    /* number of times locked */
    int64mt_t		    nbusy;	    /* number of _try() failures */
    int64mt_t		    nwait;	    /* number of times waited for lock */
    int64mt_t		    nspin;	    /* total number of spins for all nwait */
#endif
} sys_spinlock_t;

#define SYS_SPINLOCK_INIT()	{ .lockbit = SYS_LOCK_INIT() }

static always_inline void
sys_spinlock_init(sys_spinlock_t * const spinlock)
{
    *spinlock = (sys_spinlock_t)SYS_SPINLOCK_INIT();
}

#if SYS_LOCK_CHECKS	/* sys_spinlock owner tracking and checks */

  #define sys_spin_assert_holding(lockp)    assert_this_thread_is((lockp)->owner)
  #define sys_spin_assert_notholding(lockp) assert_this_thread_is_not((lockp)->owner)

  #define _sys_spin_set_owner(lockp, thread) ((lockp)->owner = (thread))

  /* Allow the owner of a lock to pass it off to a new owner (the intended unlocking task) */
  #define sys_spin_set_owner(lockp, task) \
  do { \
      sys_spin_assert_holding(lockp); \
      _sys_spin_set_owner((lockp), (task)); \
  } while (0)

#else

  #define sys_spin_assert_holding(lockp)    do { } while (0)
  #define sys_spin_assert_notholding(lockp) do { } while (0)
  #define _sys_spin_set_owner(lockp, task)  do { } while (0)
  #define sys_spin_set_owner(lockp, task)   do { } while (0)

#endif

#if SYS_LOCK_STATS	/* sys_spinlock stats */

  #define SYS_SPIN_FMT \
      "nlock=%"PRIu64" nbusy=%"PRIu64"(%u%%) nwait=%"PRIu64"(%u%%) avg_spins/wait=%"PRIu64

  #define SYS_SPIN_FIELDS(lock) \
      (lock)->nlock, (lock)->nbusy.i, PCT((lock)->nbusy.i, (lock)->nlock), \
		     (lock)->nwait.i, PCT((lock)->nwait.i, (lock)->nlock), \
      DIV((lock)->nspin.i, (lock)->nwait.i)

  #define sys_spin_unlock(lockp) \
  do { \
      sys_spin_assert_holding(lockp); \
      _sys_spin_set_owner((lockp), NULL); \
      sys_lock_release(&(lockp)->lockbit); \
  } while (0)

  #define _sys_spin_lock_try(lockp) ({ \
      bool const _ret = sys_lock_acquire_try(&(lockp)->lockbit); \
      if (likely(_ret)) { \
	  _sys_spin_set_owner((lockp), sys_thread_current()); \
	  ++(lockp)->nlock; \
      } \
      _ret; \
  })

  #define sys_spin_lock_try(lockp) ({ \
      bool const _ret = _sys_spin_lock_try(lockp); \
      if (unlikely(!_ret)) { \
	  int64mt_inc(&(lockp)->nbusy); \
      } \
      _ret; \
  })

  #define sys_spin_lock(lockp) \
  do { \
      if (unlikely(!_sys_spin_lock_try(lockp))) { \
	  int64mt_inc(&(lockp)->nwait); \
	  sys_spin_assert_notholding(lockp); \
	  do { \
	      int64mt_inc(&(lockp)->nspin); \
	      SYS_SPINWAITING(); \
	  } while (!_sys_spin_lock_try(lockp)); \
      } \
  } while (0)

#else

  #define SYS_SPIN_FMT		   "%s"
  #define SYS_SPIN_FIELDS(lock)	   ""
  #define sys_spin_unlock(lockp)   do { sys_lock_release(&(lockp)->lockbit); } while (0)
  #define sys_spin_lock_try(lockp) sys_lock_acquire_try(&(lockp)->lockbit)
  #define sys_spin_lock(lockp)	   do { } while (!sys_spin_lock_try(lockp) && SYS_SPINWAITING())

#endif

/******************************************************************************/

/*** Multiple-Reader / Multiple-Writer MT-safe FIFO (singly-linked with spinlock) ***/

typedef struct _sys_link {
    struct _sys_link * volatile next;
} sys_link_t;

typedef CACHE_ALIGNED struct {
    magic_t			magic;
    count_t	       volatile nitem;	    /* number of items in FIFO */
    int32mt_t	                hiwat;	    /* historical max number of items in FIFO */
    sys_link_t	               	head;	    /* valid only when nitem > 0 */
    sys_link_t	               	tail;	    /* valid only when nitem > 0 */
    sys_spinlock_t		lock;
} sys_fifo_t;

#define SYS_FIFO_MAGIC		0xF1F0F1F0	    /* "FIFO FIFO" */

#define SYS_FIFO_FMT		"nitem=%u hiwat=%u lock={"SYS_SPIN_FMT"}"
#define SYS_FIFO_FIELDS(fifo)	(fifo)->nitem, (fifo)->hiwat.i, SYS_SPIN_FIELDS(&(fifo)->lock)

#define SYS_FIFO_INIT()		{	.magic = SYS_FIFO_MAGIC, \
					.lock = SYS_SPINLOCK_INIT(), \
				}

/* The fifo must be locked when the check function is called */
static inline void
sys_fifo_check_locked(sys_fifo_t const * fifo)
{
    assert_eq(fifo->magic, SYS_FIFO_MAGIC);
    sys_spin_assert_holding(&fifo->lock);
    assert_imply(fifo->nitem, fifo->head.next);
    assert_imply(fifo->nitem, fifo->tail.next);
    assert_imply(fifo->nitem, fifo->tail.next->next == NULL,
		 "fifo->tail.next->next=%p->%p->%p",
		 fifo, fifo->tail.next, fifo->tail.next->next);
}

/* This is NOT MT-safe -- caller must provide locking or ensure single-thread ownership */
#define foreach_fifo_entry(fifo, encloserp, member) \
    for ((encloserp) = enclosing_record((fifo)->head, typeof(encloserp), member); \
	 (encloserp); \
	 (encloserp) = enclosing_record((encloserp)->member.next, typeof(encloserp), member))

/* NOTE: use of this function is usually racy; may need external synchronization --
 * EXCEPT: a SINGLE-consumer will never see a fifo-nitem spontaneously decrease;
 *	   a SINGLE-producer will never see a fifo-nitem spontaneously increase.
 */
static always_inline count_t
sys_fifo_nitem(sys_fifo_t * const fifo)
{
    return fifo->nitem;
}

/* NOTE: use of this function is usually racy; may need external synchronization --
 * EXCEPT: a SINGLE-consumer will never see a non-empty fifo spontaneously go empty;
 *	   a SINGLE-producer will never see an empty fifo spontaneously go non-empty.
 */
static always_inline bool
sys_fifo_is_empty(sys_fifo_t * const fifo)
{
    return sys_fifo_nitem(fifo) == 0;
}

/* For logging functions to know which fifos ever saw activity */
static always_inline bool
sys_fifo_was_used(sys_fifo_t * const fifo)
{
    return fifo->hiwat.i > 0;
}

/* Initialize a fifo to empty, unlocked, zero stats */
static inline void
sys_fifo_init(sys_fifo_t * const fifo)
{
    if (!valgrind_is_active()) expect(fifo->magic != SYS_FIFO_MAGIC); /* should deinit first */
    *fifo = (sys_fifo_t)SYS_FIFO_INIT();
}

/* Check a fifo for emptiness and trash its structure to an observable pattern */
static inline void
sys_fifo_deinit(sys_fifo_t * const fifo)
{
#if DEBUG
    sys_spin_lock(&fifo->lock);
    sys_fifo_check_locked(fifo);
    bool ok = sys_fifo_is_empty(fifo);
    expect(ok, "NON-EMPTY: fifo={"SYS_FIFO_FMT"}", SYS_FIFO_FIELDS(fifo));
    memset(fifo, 0xb9, sizeof(*fifo));
#endif
}

/* Take and return one item from the head of fifo, or NULL if empty */
/* The link pointer in the returned item is NOT cleared */
static inline sys_link_t *
sys_fifo_take(sys_fifo_t * const fifo)
{
    sys_link_t * itemlinkp = NULL;

    sys_spin_lock(&fifo->lock);
    {
	sys_fifo_check_locked(fifo);

	if (likely(fifo->nitem > 0)) {
	    itemlinkp = fifo->head.next;
	    fifo->head.next = itemlinkp->next;
	    --fifo->nitem;
	}
    }
    sys_spin_unlock(&fifo->lock);

    return itemlinkp;
}

#define sys_fifo_take_entry(fifo, type, member) \
	    enclosing_record(sys_fifo_take(fifo), type, member)

/* Add one link item at the HEAD of the fifo --
 * the incoming value of itemlinkp->next is ignored and overwritten
 */
static inline void
sys_fifo_prepend(sys_fifo_t * const fifo, sys_link_t * const itemlinkp)
{
    sys_spin_lock(&fifo->lock);
    {
	sys_fifo_check_locked(fifo);

	if (unlikely(fifo->nitem == 0)) {
	    itemlinkp->next = NULL;
	    fifo->tail.next = itemlinkp;
	} else {
	    itemlinkp->next = fifo->head.next;
	}
	fifo->head.next = itemlinkp;

	++fifo->nitem;
    }
    sys_spin_unlock(&fifo->lock);

    int32mt_hiwat(&fifo->hiwat, fifo->nitem);
}

/* Helper for appending a linked list of one or more items to a fifo --
 * f and l are the first and last items in an incoming linked chain of length nitems
 */
static inline void
_sys_fifo_append_chain(sys_fifo_t * const fifo_dst, sys_link_t * const f,
					            sys_link_t * const l, count_t const nitems)
{
    assert(f);
    assert(l);
    assert_ae(nitems, 1);
    assert_eq(l->next, NULL);

#if DEBUG
    count_t check_nitems = 0;
    sys_link_t * curr = f;
    sys_link_t * prev = NULL;
    while (curr) {
	++check_nitems;
	prev = curr;
	curr = curr->next;
    }
    assert_eq(check_nitems, nitems);
    assert_eq(prev, l);
#endif

    sys_spin_lock(&fifo_dst->lock);
    {
	sys_fifo_check_locked(fifo_dst);

	if (unlikely(fifo_dst->nitem == 0)) {
	    fifo_dst->head.next = f;	    /* fifo_dst was empty */
	} else {
	    fifo_dst->tail.next->next = f;  /* fifo_dst was non-empty */
	}
	fifo_dst->tail.next = l;

	fifo_dst->nitem += nitems;
    }
    sys_spin_unlock(&fifo_dst->lock);

    int32mt_hiwat(&fifo_dst->hiwat, fifo_dst->nitem);
}

/* Add an item to a fifo --
 * the incoming value of itemlinkp->next is ignored and overwritten
 */
static inline void
sys_fifo_append(sys_fifo_t * const fifo_dst, sys_link_t * const itemlinkp)
{
    itemlinkp->next = NULL;
    _sys_fifo_append_chain(fifo_dst, itemlinkp, itemlinkp, 1);
}

/* Add an item to the fifo in sort order (as determined by the cmp() argument) --
 * new items are placed onto the list after existing list items with equal sort key.
 */
static inline void
sys_fifo_insert_sorted(sys_fifo_t * const fifo, sys_link_t * const newlink,
                      int (*cmp)(void *, sys_link_t *, sys_link_t *), void * env)
{
    sys_spin_lock(&fifo->lock);
    {
	if (unlikely(fifo->nitem == 0)) {
	    /* Adding to empty list */
	    newlink->next = NULL;
	    fifo->tail.next = newlink;
	    fifo->head.next = newlink;
	} else {
	    /* Simple linear search */
	    sys_link_t * l;
	    for (l = &fifo->head; l != NULL; l = l->next) {
		assert(l->next != newlink);	/* assert not already on the list */
		if (unlikely(!l->next) || cmp(env, l->next, newlink) > 0) {
		    /* l->next is larger than newlink, so insert newlink after l */
		    newlink->next = l->next;
		    l->next = newlink;
		    if (!newlink->next) {
			/* l->next was NULL -- adding to the end of list */
			assert_eq(fifo->tail.next, l);	/* l was previously the tail item */
			fifo->tail.next = newlink;	/* newlink is now the tail item */
		    }
		    break;
		}
	    }
	}

	++fifo->nitem;
    }
    sys_spin_unlock(&fifo->lock);

    int32mt_hiwat(&fifo->hiwat, fifo->nitem);
}

/* Remove the linked item from the queue if it is on the queue --
 * return E_OK if the item was found (and removed), otherwise EINVAL;
 * caller remains responsible for disposing of the removed item.
 */
static inline errno_t
sys_fifo_find_remove(sys_fifo_t * const fifo, sys_link_t * const link)
{
    errno_t ret = EINVAL;

    sys_spin_lock(&fifo->lock);
    {
	sys_link_t * l;
	for (l = &fifo->head; l->next != NULL; l = l->next) {
	    trace_verbose("find_remove(compare link %p with %p l->next", link, l->next);
	    if (l->next == link) {
		l->next = link->next;
		if (!link->next) {
		    assert_eq(fifo->tail.next, link);
		    fifo->tail.next = l;
#if !OPTIMIZED
		} else {
		    link->next = (void *)MEM_ZAP_64;
#endif
		}
		--fifo->nitem;
		ret = E_OK;
		break;
	    }
	}
    }
    sys_spin_unlock(&fifo->lock);

    return ret;
}

#if 0
/* Return a pointer to the first item on queue, without removing it --
 * this can only be safe in single-consumer usage
 */
static inline sys_link_t *
_sys_fifo_first(sys_fifo_t * const fifo)
{
    sys_link_t * itemlinkp = NULL;

    sys_spin_lock(&fifo->lock);
    {
	if (likely(fifo->nitem > 0)) {
	    itemlinkp = fifo->head.next;
	}
    }
    sys_spin_unlock(&fifo->lock);

    return itemlinkp;
}
#endif

/* Transfer any and all members from fifo_src to fifo_dst --
 * fifo_src is emptied (for the instant) with its members having been appended to fifo_dst;
 * either or both fifos may start empty; returns the number of items transferred.
 */
static inline count_t
sys_fifo_xfer(sys_fifo_t * const fifo_dst, sys_fifo_t * const fifo_src)
{
    /* Doing this preliminary check unlocked is no racier than we already are here, because if
     * we instead made the decision (to return because nitems_xfer == 0) while under a lock, the
     * same race could occur as soon as we dropped the lock before returning.  It's intrinsic
     * that a transfer from a fifo with other writer threads leaves no guarantee that the source
     * fifo is still empty upon return.  It doesn't matter here, as this is only an optimization.
     */
    if (unlikely(fifo_src->nitem == 0)) return 0;	/* source fifo empty -- nothing to do */

    sys_link_t * f = NULL;		/* first new entry from fifo_src */
    sys_link_t * l = NULL;		/* last new entry from fifo_src */
    count_t nitems_xfer;

    /* Source appeared non-empty -- lock it and grab whatever we find there after locking */
    sys_spin_lock(&fifo_src->lock);
    {
	nitems_xfer = fifo_src->nitem;	/* recheck nitems under lock (validity of f, l) */
	if (likely(nitems_xfer > 0)) {
	    f = fifo_src->head.next;	/* grab the src fifo's pointers */
	    l = fifo_src->tail.next;
	    /* our convention here is that a fifo's pointers are only good when nitem != 0 */
	    fifo_src->nitem = 0;	/* empty out the src fifo */
	}
    }
    sys_spin_unlock(&fifo_src->lock);

    if (likely(nitems_xfer > 0)) {
	/* Now add to fifo_dst what we grabbed above */
	_sys_fifo_append_chain(fifo_dst, f, l, nitems_xfer);
    }

    return nitems_xfer;
}

/* Transfer all but (max_leave) members from fifo_src to fifo_dst --
 * returns the number of items transferred
 */
extern count_t sys_fifo_xfer_leave(sys_fifo_t * const fifo_dst,
				   sys_fifo_t * const fifo_src, count_t const max_leave);

/* Transfer up to (max_xfer) members from fifo_src to fifo_dst --
 * returns the number of items transferred
 */
extern count_t sys_fifo_xfer_max(sys_fifo_t * const fifo_dst,
				 sys_fifo_t * const fifo_src, count_t const max_xfer);

/******************************************************************************/

/* Multiple-Reader / Multiple-Writer MT-safe FIFO queue --
 *
 * The sys_fifo_t data structure is a linked-list FIFO queue using sys_link_t.  sys_mwqueue_t
 * embeds two of those in separate cache lines, one used for writing and the other for reading.
 *
 * Appended items are always always added to write_fifo.  Reader takes from read_fifo until it
 * is empty, then atomically transfers everything from write_fifo to read_fifo in constant time.
 *
 * Prepending to the mwqueue is also allowed -- items are prepended to read_fifo.
 */
typedef CACHE_ALIGNED struct {
    magic_t		    write_magic;
    uint32_t		    spare;
    sys_fifo_t		    write_fifo;		    /* writers add here */
#if TRACE_STATS
    int64mt_t		    nappend;
    int64mt_t		    nitem_append;
#endif
  CACHE_ALIGNED
    sys_fifo_t		    read_fifo;		    /* readers read from here */
    magic_t		    read_magic;
#if TRACE_STATS
    int64mt_t		    nitem_take;
    int64mt_t		    ntake_empty;
    int64mt_t		    nitem_prepend;
    int64mt_t		    nxfers;
#endif
} sys_mwqueue_t;

#define SYS_MWQUEUE_MAGIC 0x12341234

#if TRACE_STATS

#define SYS_MWQUEUE_FMT \
    "nappend=%-8"PRIu64" nitem_append=%-8"PRIu64 \
    " nitem_take=%-8"PRIu64" ntake_empty=%-6"PRIu64" (%u%%)" \
    " nprepend=%-6"PRIu64 " nxfers=%-6"PRIu64 \
    " avg_items/xfer=%-5"PRIu64 \
    "\n\t\twrite_fifo={"SYS_FIFO_FMT"}" \
    "\n\t\tread_fifo={"SYS_FIFO_FMT"}"

#define SYS_MWQUEUE_FIELDS(mwq) \
    (mwq)->nappend.i, (mwq)->nitem_append.i, \
    (mwq)->nitem_take.i, (mwq)->ntake_empty.i, PCT((mwq)->ntake_empty.i, (mwq)->nitem_take.i), \
    (mwq)->nitem_prepend.i, (mwq)->nxfers.i, \
    DIV((mwq)->nitem_take.i, (mwq)->nxfers.i), \
    SYS_FIFO_FIELDS(&(mwq)->write_fifo), \
    SYS_FIFO_FIELDS(&(mwq)->read_fifo)

#else	/* !TRACE_STATS */

#define SYS_MWQUEUE_FMT			"%s"
#define SYS_MWQUEUE_FIELDS(fl)		"no mwqueue_stats when !TRACE_STATS"

#endif	/* !TRACE_STATS */

#define sys_mwqueue_stats(mwq) sys_sprintf(SYS_MWQUEUE_FMT, SYS_MWQUEUE_FIELDS(mwq))

static inline void
sys_mwqueue_check_reader(sys_mwqueue_t * const mwq)
{
    assert(mwq);
    assert_eq(mwq->read_magic, SYS_MWQUEUE_MAGIC);
}

static inline void
sys_mwqueue_check_writer(sys_mwqueue_t * const mwq)
{
    assert_eq(mwq->write_magic, SYS_MWQUEUE_MAGIC);
}

#define SYS_MWQUEUE_INIT()	{ \
				    .write_magic = SYS_MWQUEUE_MAGIC, \
				    .write_fifo = SYS_FIFO_INIT(), \
				    .read_magic = SYS_MWQUEUE_MAGIC, \
				    .read_fifo = SYS_FIFO_INIT(), \
				}

static inline void
sys_mwqueue_init(sys_mwqueue_t * const mwq)
{
    expect(mwq->write_magic != SYS_MWQUEUE_MAGIC);
    expect(mwq->read_magic != SYS_MWQUEUE_MAGIC);
    *mwq = (sys_mwqueue_t)SYS_MWQUEUE_INIT();
    sys_mwqueue_check_reader(mwq);
    sys_mwqueue_check_writer(mwq);
}

static inline void
sys_mwqueue_deinit(sys_mwqueue_t * const mwq)
{
    sys_mwqueue_check_reader(mwq);
    sys_mwqueue_check_writer(mwq);
#if TRACE_STATS
    expect_eq(mwq->nitem_take.i, mwq->nitem_append.i + mwq->nitem_prepend.i);
#endif
    memset(mwq, 0xb9, sizeof(*mwq));
}

/* NOTE: use of this function is inherently racy; may require external synchronization --
 * EXCEPT: a single-reader will never see a non-empty queue spontaneously go empty;
 *	   a single-writer will never see an empty queue spontaneously go non-empty.
 */
static inline bool
sys_mwqueue_is_empty(sys_mwqueue_t * const mwq)
{
    return sys_fifo_is_empty(&mwq->read_fifo) && sys_fifo_is_empty(&mwq->write_fifo);
}

/* Take and return the first item from the mwqueue, returning NULL if empty --
 * the returned queue_item's link field is NOT cleared
 */
static inline sys_link_t *
sys_mwqueue_take(sys_mwqueue_t * const mwq)
{
    sys_mwqueue_check_reader(mwq);
    sys_link_t * itemlinkp;
    count_t nitems_xfer;

    while (!(itemlinkp = sys_fifo_take(&mwq->read_fifo))) {
	nitems_xfer = sys_fifo_xfer(&mwq->read_fifo, &mwq->write_fifo);
	if (unlikely(nitems_xfer == 0)) {
#if TRACE_STATS
	    int64mt_inc(&mwq->ntake_empty);
#endif
	    return NULL;
	}
#if TRACE_STATS
	int64mt_inc(&mwq->nxfers);
#endif
    }

#if TRACE_STATS
    int64mt_inc(&mwq->nitem_take);
#endif
    return itemlinkp;
}

#define sys_mwqueue_take_entry(mwq, type, member) \
	    enclosing_record(sys_mwqueue_take(mwq), type, member)

/* Prepend an item to the HEAD of the mwqueue */
static inline void
sys_mwqueue_prepend(sys_mwqueue_t * const mwq, sys_link_t * const itemlinkp)
{
    sys_mwqueue_check_reader(mwq);

    sys_fifo_prepend(&mwq->read_fifo, itemlinkp);
#if TRACE_STATS
    int64mt_inc(&mwq->nitem_prepend);
#endif
}

/* Append an item to the mwqueue --
 * the incoming value of itemlinkp->next is ignored and overwritten
 */
static inline void
sys_mwqueue_append(sys_mwqueue_t * const mwq, sys_link_t * const itemlinkp)
{
    sys_mwqueue_check_writer(mwq);
    assert(itemlinkp);

    sys_fifo_append(&mwq->write_fifo, itemlinkp);

#if TRACE_STATS
    int64mt_inc(&mwq->nitem_append);
    int64mt_inc(&mwq->nappend);
#endif
}

/* Transfer a fifo of items contiguously to the mwqueue --
 * returns the number of items transferred
 */
static inline count_t
sys_mwqueue_append_fifo(sys_mwqueue_t * const mwq, sys_fifo_t * const fifo)
{
    sys_mwqueue_check_writer(mwq);

    count_t const nitems_xfer = sys_fifo_xfer(&mwq->write_fifo, fifo);

#if TRACE_STATS
    int64mt_add(&mwq->nitem_append, nitems_xfer);
    int64mt_inc(&mwq->nappend);
#endif

    return nitems_xfer;
}

/******************************************************************************/

/* Freelist cache with limited per-CPU hoards to reduce cross-thread contention */

#define MAX_CPU 4	//XXXX

static always_inline uint32_t
my_cpu(void)
{
    int ret = sched_getcpu();
    expect_rc(ret, sched_getcpu());
    if (unlikely(ret >= MAX_CPU)) {
	static bool been_here = false;
	if (!been_here) {
	    sys_warning("sched_getcpu (%d) >= (%d) MAX_CPU -- increase MAX_CPU", ret, MAX_CPU);
	    been_here = true;
	}
	ret = MAX_CPU-1;
    }
    return ret;
}

#define MAX_HOARDS MAX_CPU	//XXX

static always_inline uint32_t
my_hoard(void)
{
    int const ret = my_cpu();
    assert_be(ret, MAX_HOARDS-1);
    return ret;
}

typedef CACHE_ALIGNED struct {
    sys_fifo_t		    hoard;
    int32mt_t		    hoard_limit;    /* (soft) max number of items allowed in hoard */
#if TRACE_STATS
    int64mt_t		    nitem_add;
    int64mt_t		    nitem_take;
    int64mt_t		    ntake_empty;
    int64mt_t		    nxfers_in;
    int64mt_t		    nxfer_items_in;
    int64mt_t		    nxfers_out;
#endif
} sys_freelist_hoard_t;

typedef struct {
    magic_t		    magic;
    count_t		    nhoard;
    sys_fifo_t		    common;
    sys_freelist_hoard_t    hoard[MAX_HOARDS];
} sys_freelist_t;

#define SYS_FREELIST_MAGIC  0x4e4e4e4e	    /* "FREE FREE FREE FREE" */

#define SYS_FREELIST_HOARD_INIT(HOARD_LIMIT) \
				{ \
					.hoard = SYS_FIFO_INIT(), \
					.hoard_limit = { HOARD_LIMIT }, \
				}

assert_static(MAX_HOARDS == 4);	/* ensure init of each array element */
#define SYS_FREELIST_INIT(HOARD_LIMIT) { \
					.magic = SYS_FREELIST_MAGIC, \
					.nhoard = MAX_HOARDS, \
					.common = SYS_FIFO_INIT(), \
					.hoard[0] = SYS_FREELIST_HOARD_INIT(HOARD_LIMIT), \
					.hoard[1] = SYS_FREELIST_HOARD_INIT(HOARD_LIMIT), \
					.hoard[2] = SYS_FREELIST_HOARD_INIT(HOARD_LIMIT), \
					.hoard[3] = SYS_FREELIST_HOARD_INIT(HOARD_LIMIT), \
				      }

#if TRACE_STATS

#define SYS_FREELIST_HOARD_FMT \
    " limit=%u" \
    " nadd=%-8"PRIu64" nxfer_out=%-5"PRIu64" ntake_empty=%-6"PRIu64 \
    " ntake=%-8"PRIu64" nxfer_in=%-5"PRIu64" avg_count/xfer_in=%-5"PRIu64 \
    "\n\t    fifo={"SYS_FIFO_FMT"}"

#define SYS_FREELIST_HOARD_FIELDS(flhoard) \
    (flhoard)->hoard_limit.i, \
    (flhoard)->nitem_add.i, (flhoard)->nxfers_out.i, (flhoard)->ntake_empty.i, \
    (flhoard)->nitem_take.i, (flhoard)->nxfers_in.i, \
	DIV((flhoard)->nxfer_items_in.i, (flhoard)->nxfers_in.i), \
    SYS_FIFO_FIELDS(&(flhoard)->hoard)

#define SYS_FREELIST_FMT \
    "\n\thoard[0]={"SYS_FREELIST_HOARD_FMT"}" \
    "\n\thoard[1]={"SYS_FREELIST_HOARD_FMT"}" \
    "\n\thoard[2]={"SYS_FREELIST_HOARD_FMT"}" \
    "\n\thoard[3]={"SYS_FREELIST_HOARD_FMT"}" \
    "\n\tcommon={"SYS_FIFO_FMT"}"

#define SYS_FREELIST_FIELDS(fl) \
    SYS_FREELIST_HOARD_FIELDS(&(fl)->hoard[0]), \
    SYS_FREELIST_HOARD_FIELDS(&(fl)->hoard[1]), \
    SYS_FREELIST_HOARD_FIELDS(&(fl)->hoard[2]), \
    SYS_FREELIST_HOARD_FIELDS(&(fl)->hoard[3]), \
    SYS_FIFO_FIELDS(&(fl)->common) \

#else	/* !TRACE_STATS */

#define SYS_FREELIST_FMT		"%s"
#define SYS_FREELIST_FIELDS(fl)		"no freelist_stats when !TRACE_STATS"

#endif	/* !TRACE_STATS */

#define sys_freelist_stats(fl) sys_sprintf(SYS_FREELIST_FMT, SYS_FREELIST_FIELDS(fl))

static inline void
sys_freelist_check(sys_freelist_t * const fl)
{
    assert_eq(fl->magic, SYS_FREELIST_MAGIC);
    assert_be(fl->nhoard, NELEM(fl->hoard));
}

static inline void
sys_freelist_init(sys_freelist_t * const fl,
		  /*count_t const nhoard, count_t const*/ count_t hoard_limit)
{
    count_t const nhoard = MAX_HOARDS;

    verify_be(nhoard, NELEM(fl->hoard));
    expect(fl->magic != SYS_FREELIST_MAGIC);

    *fl = (sys_freelist_t)SYS_FREELIST_INIT(hoard_limit);
    fl->nhoard = nhoard;

    sys_freelist_check(fl);
}

static inline void
sys_freelist_deinit(sys_freelist_t * const fl)
{
    sys_freelist_check(fl);
    bool ok = sys_fifo_is_empty(&fl->common);
    assert(ok, "NON-EMPTY: fifo={"SYS_FIFO_FMT"}", SYS_FIFO_FIELDS(&fl->common));

    idx_t hoardn;
    for (hoardn = 0; hoardn < fl->nhoard; hoardn++) {
	ok = sys_fifo_is_empty(&fl->hoard[hoardn].hoard);
	assert(ok, "NON-EMPTY: fifo={"SYS_FIFO_FMT"}",
			SYS_FIFO_FIELDS(&fl->hoard[hoardn].hoard));
    }

    memset(fl, 0xb9, sizeof(*fl));
}

/* Take an item from the freelist --
 * the returned fifo_item's link field is NOT cleared
 */
static inline sys_link_t *
sys_freelist_hoard_take(sys_freelist_t * const fl, idx_t const hoardnum)
{
    assert_be(hoardnum, MAX_HOARDS-1);
    assert_be(hoardnum, fl->nhoard-1);

    sys_freelist_hoard_t * const hoard = &fl->hoard[hoardnum];
    sys_link_t * itemlinkp;
    count_t nitems_xfer = 0;

    while (unlikely(!(itemlinkp = sys_fifo_take(&hoard->hoard)))) {
	/* The hoard is empty -- try to fill up to half of it from the common pool */
	uint32_t const hoard_limit = int32mt_get(&hoard->hoard_limit);
	nitems_xfer = sys_fifo_xfer_max(&hoard->hoard, &fl->common, 1 + hoard_limit/2);
	if (unlikely(nitems_xfer == 0)) {
#if TRACE_STATS
	    int64mt_inc(&hoard->ntake_empty);
#endif
	    return NULL;
	}
#if TRACE_STATS
	int64mt_inc(&hoard->nxfers_in);
	int64mt_add(&hoard->nxfer_items_in, nitems_xfer);
#endif
    }

#if TRACE_STATS
    int64mt_inc(&hoard->nitem_take);
#endif
    return itemlinkp;
}

#define sys_freelist_hoard_take_entry(fl, hoard, type, member) \
	    enclosing_record(sys_freelist_hoard_take((fl), (hoard)), type, member)

/* Take an item from the freelist --
 * the returned fifo_item's link field is NOT cleared
 */
static inline sys_link_t *
sys_freelist_take(sys_freelist_t * const fl)
{
    return sys_freelist_hoard_take(fl, my_hoard());
}

#define sys_freelist_take_entry(fl, type, member) \
	    enclosing_record(sys_freelist_take(fl), type, member)

/* Add an item to the freelist --
 * the pre-existing value of itemlinkp->next is ignored and overwritten.
 * Note that it *is* possible for multiple threads to be concurrently accessing the same hoard
 */
static inline void
sys_freelist_add(sys_freelist_t * const fl, sys_link_t * const itemlinkp)
{
    assert(itemlinkp);

    uint32_t const hoardnum = my_hoard();
    assert_be(hoardnum, MAX_HOARDS-1);
    assert_be(hoardnum, fl->nhoard-1);

    sys_freelist_hoard_t * const hoard = &fl->hoard[hoardnum];
    sys_fifo_append(&hoard->hoard, itemlinkp);
#if TRACE_STATS
    int64mt_inc(&hoard->nitem_add);
#endif

    //XXX It would be more efficient code if hoard_limit were defined at compile-time
    //XXX but I'm thinking of adjusting it dynamically in response to memory pressure
    uint32_t hoard_limit = int32mt_get(&hoard->hoard_limit);
    if (likely(sys_fifo_nitem(&hoard->hoard) <= hoard_limit)) {
	return;
    }

    /* The hoard is too full -- give all but half of it to the common pool */
    //XXX Maybe defer the xfer until next time if the lock is busy?
    sys_fifo_xfer_leave(&fl->common, &hoard->hoard, 1 + hoard_limit/2);
#if TRACE_STATS
    int64mt_inc(&hoard->nxfers_out);
#endif
}

#endif /* SYS_MTTYPES_H */
