/*
 * mm-naive.c - The least memory-efficient malloc package.
 * 
 * In this naive approach, a block is allocated by allocating a
 * new page as needed.  A block is pure payload. There are no headers or
 * footers.  Blocks are never coalesced or reused.
 *
 * The heap check and free check always succeeds, because the
 * allocator doesn't depend on any of the old data.
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "mm.h"
#include "memlib.h"

#define DEBUG 1

/* Macros for compact header and footer */
/* #define GET(p)      (*(int *)(p))
#define GET_ALLOC(p) (GET(p) & 0x1)
#define GET_SIZE(p)  (GET(p) & ~0xF)
#define PUT(p, val) (*(int *)(p) = (val))
#define PACK(size, alloc) ((size) | (alloc))
typedef int block_header;
typedef int block_footer; */ // TODO implement this later

/* Free List Implementation */
typedef struct list_node {
    struct list_node *prev;
    struct list_node *next;
} list_node; // TODO: currently only used for pages.

/* Macros for noncompact header and footer */
#define GET_ALLOC(p) ((block_header *)(p))->allocated
#define GET_SIZE(p) ((block_header *)(p))->size
#define OVERHEAD (sizeof(block_header)+sizeof(block_footer))
/* custom macros */
#define FIRST_BP_PAYLOAD_OFFSET ALIGN(sizeof(list_node) + OVERHEAD + sizeof(block_header))
#define PROLOGUE_PAYLOAD_OFFSET (FIRST_BP_PAYLOAD_OFFSET - sizeof(block_header) - sizeof(block_footer))
#define FIRST_BP_SIZE(size) (size - FIRST_BP_PAYLOAD_OFFSET - sizeof(block_footer) + sizeof(block_header))

#define HDRP(ptr) ((char *)(ptr) - sizeof(block_header))
#define FTRP(ptr) ((char *)(ptr)+GET_SIZE(HDRP(ptr))-OVERHEAD)
#define NEXT_BLKP(ptr) ((char *)(ptr)+GET_SIZE(HDRP(ptr)))
#define PREV_BLKP(ptr) ((char *)(ptr)-GET_SIZE((char *)(ptr)-OVERHEAD))
/* always use 16-byte alignment */
#define ALIGNMENT 16
/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))
/* rounds up to the nearest multiple of mem_pagesize() */
#define PAGE_ALIGN(size) (((size) + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1))
#define PAGE_SIZE (mem_pagesize() << 1)// same as mem_pagesize
#define GET_NEXT_PAGE(p) ((list_node *)(p))->next
#define GET_PREV_PAGE(p) ((list_node *)(p))->prev

typedef struct {
    size_t size;
    char allocated;
} block_header;

typedef struct {
    size_t size;
    int filler;
} block_footer;

void *free_list = NULL;
void *first_page = NULL;
/*
 * mm_init - initialize the malloc package.
 Before calling mm_malloc or mm_free, the application program (i.e.,
 the trace-driven driver program that you will use to evaluate your
 implementation) calls mm_init to perform any necessary initialization,
 such as allocating the initial heap area. The return value should be
 -1 if there was a problem in performing the initialization, 0 otherwise.

 The mm_init function will be called once per benchmark run, so it can be
 called multiple times in the same run of mdriver. Your mm_init function
 should reset your implementation to its initial state in each case.
 */
int mm_init(void)
{
  if(DEBUG) printf("\nmm_init called\n");
  // Reset all local variables
  free_list = NULL;
  first_page = NULL;

  // unmaping pages will be done automatically
  return 0;
}

/*
 * mm_check - Check whether the heap is ok, so that mm_malloc()
 *            and proper mm_free() calls won't crash.
 * Checks whether the heap is well-formed so that calls to mm_malloc
 * and mm_free will behave correctly and not cause a crash, in which
 * case it returns 1. The mm_check must return 0 if the heap has been
 * corrupted by the client so that mm_malloc and mm_free cannot behave
 * correctly or might crash.
 *
 * The intent is that a client can use mm_check to help debug their own
 * code—but you will likely find that mm_check is useful for debugging
 * the allocator, too. We will test mm_check by calling it multiple
 * times during a well-behaved client to make sure that it always
 * returns 1. We will also test mm_check with a chaotic client that
 * randomly and incorrectly writes to memory that is outside allocated
 * regions returned by mm_malloc; in that case, mm_check might return 0
 * to indicate that the heap is too corrupted to continue, or it may return 1
 * as long as mm_malloc and mm_free will still not crash—at least when mm_free
 * is only called on pointers for which mm_can_free returns 1.
 *
 * The mm_check function is not obligated to detect arbitrary misbehavior
 * by a client. For example, if a client program mangles the heap in a way
 * that turns out to be a different but consistent state as far as the allocator
 * is concerned, then mm_check can return 1. The mm_check function is only
 * obligated to detect heap changes that prevent the allocator’s other
 * functions from working without crashing.
 */
int mm_check()
{
  if(DEBUG) printf("\nmm_check called\n");
  // start at beginning of memory.
  void *current_page = first_page;
  void *current_ptr = first_page + PROLOGUE_PAYLOAD_OFFSET;
  if(0) printf("\ncurrent_ptr is %p it should be the same as first payload pointer\n", current_ptr);
  if(GET_SIZE(HDRP(current_ptr)) != OVERHEAD && !GET_ALLOC(HDRP(current_ptr)) && GET_SIZE(FTRP(current_ptr)) != OVERHEAD) {
    if(DEBUG) printf("prologue screwed up.\n");
    return 0;
  }
  do {
    while(1) {
      if(DEBUG) printf("[%d/%d]", (int)GET_SIZE(HDRP(current_ptr)), (int)GET_ALLOC(HDRP(current_ptr)));
      if(GET_SIZE(HDRP(current_ptr)) == 0 && GET_ALLOC(HDRP(current_ptr))) { // Go till we hit null terminator
        break;
      }
      else if (GET_SIZE(HDRP(current_ptr)) == 0 && !GET_ALLOC(HDRP(current_ptr))) {
        if(DEBUG) printf("\nFound block [0/0] at %p which doesn't make any sense.\n", current_ptr);
        return 0;
      }
      else {
        //if(DEBUG) printf("%p[%d] ", current_ptr, (int)GET_SIZE(FTRP(current_ptr))); // print current footer
        if(DEBUG) printf("[%d] ", (int)GET_SIZE(FTRP(current_ptr))); // print current footer
        current_ptr = NEXT_BLKP(current_ptr);
      }
    }
    if(DEBUG) printf("\n");
  } while(0);//GET_NEXT_PAGE(current_page) != NULL);

  return 1;
}

/*
 * mm_check - Check whether freeing the given `p`, which means that
 *            calling mm_free(p) leaves the heap in an ok state.
 *
 * Takes a pointer and returns 1 if the pointer would be a valid
 * argument to mm_free, and it returns 0 if the pointer is an invalid
 * argument to mm_free. A valid pointer is one that was returned by a
 * previous call to mm_malloc and not yet passed to mm_free.
 *
 * If the client program is misbehaved and corrupts the heap, then
 * mm_can_free is allowed to return 0 even if the given pointer was
 * from a previous call to mm_malloc and not yet passed to mm_free.
 * More generally, if mm_check returns 1 and mm_can_free returns 1 for
 * a given pointer, then mm_free on the pointer must not crash, and it
 * must leave the allocator in a state such that mm_check returns 1.
 */
int mm_can_free(void *p)
{
  if(DEBUG) printf("\nmm_can_free called\n");
  return 1;
}

void add_to_free_list(void *ptr) {
  // Todo tie ptr to the top of the free_list and change the free_list to point to ptr
//  free_list = ptr;
}
void remove_from_free_list(void *ptr) {

}

void *extend(size_t new_size) {
  if(DEBUG) printf("\nextend(%d) called\n", (int)new_size);

  int extend_debug = 0;
  size_t page_size = PAGE_ALIGN(new_size); // Arbitrary chose of 2^13 chunk size
  void *base_ptr = mem_map(page_size);

  if(first_page == NULL) // Add a starting point, if not one currently
    first_page = base_ptr;

  // Set page header TODO:
   GET_PREV_PAGE(base_ptr) = NULL;
   GET_NEXT_PAGE(base_ptr) = NULL;

  // Prologue
  void *prologue_payload = base_ptr + PROLOGUE_PAYLOAD_OFFSET;
  if(extend_debug) printf("prologue_payload at %p to [%d/1]\n", prologue_payload, (int)OVERHEAD);
  // Set prologue
  /* PUT(HDRP(prologue_payload), PACK(OVERHEAD, 1)); // TODO: implement 8 byte overhead
   PUT(FTRP(prologue_payload), PACK(OVERHEAD, 0)); */ // TODO: implement 8 byte overhead
  GET_SIZE(HDRP(prologue_payload)) = OVERHEAD;
  GET_ALLOC(HDRP(prologue_payload)) = 1;
  GET_SIZE(FTRP(prologue_payload)) = OVERHEAD;

  // Payload
  void *payload_ptr = base_ptr + FIRST_BP_PAYLOAD_OFFSET; // at first payload
  // Set payload
  if(extend_debug) printf("setting first payload at %p to size %d\n", payload_ptr, (int)FIRST_BP_SIZE(page_size));
  /* PUT(HDRP(payload_ptr), PACK(block_size, 0)); // TODO: implement 8 byte overhead
   PUT(FTRP(payload_ptr), PACK(block_size, 0)); */ // TODO: implement 8 byte overhead
  GET_SIZE(HDRP(payload_ptr)) = FIRST_BP_SIZE(page_size);
  GET_ALLOC(HDRP(payload_ptr)) = 0;
  GET_SIZE(FTRP(payload_ptr)) = FIRST_BP_SIZE(page_size);

  // Epilogue
  void *epilogue_payload = NEXT_BLKP(payload_ptr);
  if(extend_debug) printf("setting prologue at %p to [0/1]\n", epilogue_payload);
  // Set epilogue
  /* PUT(HDRP(epilogue_payload), PACK(0, 1));
   */ // TODO: implement 8 byte overhead
  GET_SIZE(HDRP(epilogue_payload)) = 0;
  GET_ALLOC(HDRP(epilogue_payload)) = 1;
  return payload_ptr;
}


// Marking a block as allocated.
void set_allocated(void *ptr, size_t size) {
  size_t extra_size = GET_SIZE(HDRP(ptr)) - size;
  if(extra_size > ALIGN(1 + OVERHEAD)) { // if there's extra room.
    GET_SIZE(HDRP(ptr)) = size;
    GET_SIZE(FTRP(ptr)) = size;
    GET_SIZE(HDRP(NEXT_BLKP(ptr))) = extra_size;
    GET_SIZE(FTRP(NEXT_BLKP(ptr))) = extra_size;
    GET_ALLOC(HDRP(NEXT_BLKP(ptr))) = 0;
  }
  GET_ALLOC(HDRP(ptr)) = 1;
}

/*
 * mm_malloc - Allocate a block by using bytes from current_avail,
 *     grabbing a new page if necessary.
 *
 * Returns a pointer to an allocated  block payload of at least size
 * bytes, where size is less than 232. The entire allocated block
 * should lie within the heap region and  should not overlap with
 * any other allocated block.
 *
 * We’ll compare your implementation to the version of malloc supplied
 * in the standard C library (libc). Since the libc malloc always returns
 * payload pointers that are aligned to 16 bytes, your malloc implementation
 * should do likewise and always return 16-byte aligned pointers. *
 */
void *mm_malloc(size_t size)
{
//  if(DEBUG) printf("\nmm_malloc(%d) called\n",(int)size);
//  int newsize = ALIGN(size);
  void *bp = NULL;
  // very first malloc

  int need_size = size > sizeof(list_node) ? size : sizeof(list_node);
  int newsize = ALIGN(need_size + OVERHEAD);


  if(first_page == NULL) {
    bp = extend(newsize);
    mm_check();
  }
  else {
//    mm_check();
    bp = first_page + FIRST_BP_PAYLOAD_OFFSET;
  }


  void *best_bp = NULL;
  while (GET_SIZE(HDRP(bp)) != 0) {
    if (!GET_ALLOC(HDRP(bp)) && (GET_SIZE(HDRP(bp)) >= newsize)) {
      if (!best_bp /* not found a allocated block yet */ || (GET_SIZE(HDRP(bp)) < GET_SIZE(HDRP(best_bp))))
          best_bp = bp;
    }
    bp = NEXT_BLKP(bp);
  }
  if (best_bp) {
    set_allocated(best_bp, newsize);
    return best_bp;
  }
  return  NULL;
  // Loop through page to find the first free spot that's big enough.
//  while (GET_SIZE(HDRP(bp)) != 0) {
//    if (!GET_ALLOC(HDRP(bp)) && (GET_SIZE(HDRP(bp)) >= newsize)) {
//      if(DEBUG) printf("Found free block [%d/%d] at %p setting it to size %d\n", (int) GET_SIZE(HDRP(bp)), (int) GET_ALLOC(HDRP(bp)), bp,(int)newsize);
//      set_allocated(bp, newsize);
//      return bp;
//    }
//    if(DEBUG) printf("Block [%d/%d] at %p won't work moving onto next block\n", (int) GET_SIZE(HDRP(bp)), (int) GET_ALLOC(HDRP(bp)), bp);
//    bp = NEXT_BLKP(bp);
//    if(DEBUG) printf("Now trying [%d/%d] at %p\n", (int) GET_SIZE(HDRP(bp)), (int) GET_ALLOC(HDRP(bp)), bp);
//  }
  // If we haven't found a free spot for it by now we need to extend.
  if(DEBUG) printf("Couldn't find free block, now extending\n");
  bp = extend(newsize);
  set_allocated(bp, newsize);
  return bp;
  /* int need_size = max(size, sizeof(list_node));
  int newsize = ALIGN(need_size + OVERHEAD);
  void *best_ptr = NULL;
  while (GET_SIZE(HDRP(ptr)) != 0) {
    if (!GET_ALLOC(HDRP(ptr)) && (GET_SIZE(HDRP(ptr)) >= new_size)) {
      if (!best_ptr *//* not found a allocated block yet *//* || (GET_SIZE(HDRP(ptr)) < GET_SIZE(HDRP(best_ptr))))
        best_ptr = ptr;
    }
    ptr = NEXT_BLKP(ptr);
  }
  if (best_ptr) {
    set_allocated(best_ptr, new_size);
    return best_ptr;
  } */ // TODO: Implement best fit and free list later

}



void *coalesce(void *ptr) {
  size_t prev_alloc = GET_ALLOC(HDRP(PREV_BLKP(ptr)));
  size_t next_alloc = GET_ALLOC(HDRP(NEXT_BLKP(ptr)));
  size_t size = GET_SIZE(HDRP(ptr));

  if(prev_alloc && next_alloc) {  /* Case 1 */
    /* nothing to do (no merge) */
    // ADD CURRENT TO FREE LIST
    add_to_free_list((list_node *)ptr);
  } else if (prev_alloc && !next_alloc) { /* Case 2 */
    /* next block */
    // ADD CURRENT TO FREE LIST AND REMOVE NEXT_BLKP FROM FREE LIST <MALLOC 18: EXPLICIT FREE LISTS 3:41>
    add_to_free_list((list_node *)ptr);
    remove_from_free_list((list_node *)NEXT_BLKP(ptr));
    size += GET_SIZE(HDRP(NEXT_BLKP(ptr)));
    GET_SIZE(HDRP(ptr)) = size; // Have to set header first so finding footer will work.
    GET_SIZE(FTRP(ptr)) = size;
  } else if (!prev_alloc && next_alloc) { /* Case 3 */
    /* prev block */
    // DON'T ADD CURRENT TO FREE LIST <MALLOC 18: EXPLICIT FREE LISTS 3:41>
    size += GET_SIZE(HDRP(PREV_BLKP(ptr)));
    GET_SIZE(FTRP(ptr)) = size; // Have to set footer first so finding header will work.
    GET_SIZE(HDRP(PREV_BLKP(ptr))) = size;
    ptr = PREV_BLKP(ptr);
  } else {    /* Case 4 */
    /* both blocks */
    // REMOVE NEXT_BLKP FROM FREE LIST AND DON'T ADD CURRENT TO FREE LIST <MALLOC 18: EXPLICIT FREE LISTS 3:41>
    remove_from_free_list((list_node *)NEXT_BLKP(ptr));
    size += (GET_SIZE(HDRP(PREV_BLKP(ptr))) + GET_SIZE(HDRP(NEXT_BLKP(ptr))));
    GET_SIZE(HDRP(PREV_BLKP(ptr))) = size;
    GET_SIZE(FTRP(NEXT_BLKP(ptr))) = size;
    ptr = PREV_BLKP(ptr);
  }
  return ptr;
}


/*
 * mm_free - Freeing a block does nothing.
 * Frees the block pointed to by ptr. It returns nothing.
 *
 * This routine is only required to work when mm_can_free(ptr)
 * returns 1. In particular, it will always work for a correctly
 * behaved client that provides a ptr returned by an earlier call
 * to mm_malloc and not yet freed via mm_free.
 */
void mm_free(void *ptr) {
  if(DEBUG) printf("\nmm_free(%p) called\n", ptr);
  if(DEBUG) printf("\ntrying to free block [%d/%d] at %p\n", (int)GET_SIZE(HDRP(ptr)), (int)GET_ALLOC(HDRP(ptr)), ptr);
  GET_ALLOC(HDRP(ptr)) = 0;
  coalesce(ptr);
}