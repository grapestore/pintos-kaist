/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "lib/kernel/hash.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"
#include "intrinsic.h"
#include <string.h>
#include "threads/vaddr.h"

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */

static struct lock spt_kill_lock;

void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
	lock_init(&spt_kill_lock);
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {


	struct supplemental_page_table *spt = &thread_current ()->spt;
	bool writable_aux = writable;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		ASSERT(type != VM_UNINIT);
		struct page* page = malloc (sizeof (struct page));
		/* TODO: Insert the page into the spt. */
		if (VM_TYPE(type) == VM_ANON){
			uninit_new (page, upage, init, type, aux, anon_initializer);
		}
		else if (VM_TYPE(type) == VM_FILE){
			uninit_new (page, upage, init, type, aux, file_map_initializer);
		}

		page -> writable = writable_aux;
		spt_insert_page (spt, page);
		return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page page;
	page.va = pg_round_down (va);
	struct hash_elem *e = hash_find (spt -> page_table, &page.hash_elem);
	if (e == NULL) return NULL;
	struct page* result = hash_entry (e, struct page, hash_elem);
	ASSERT((va < result -> va + PGSIZE) && va >= result -> va);
	return result;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt,
		struct page *page) {
	struct hash_elem *result= hash_insert (spt -> page_table, &page -> hash_elem);
	return (result == NULL) ? true : false ;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame * frame = malloc (sizeof (struct frame));
	frame -> kva = palloc_get_page (PAL_USER);
	frame -> page = NULL;

	ASSERT (frame->kva != NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	void *stack_top = pg_round_down (addr);
	size_t new_stack_size = USER_STACK - (uintptr_t)stack_top;
	if (new_stack_size > (1 << 20)) PANIC("Stack limit exceeded!\n"); // 1MB

/* spt table의 new stack page단위로 업로드 */
	void *spt_stack_page_update = stack_top;
	while((uintptr_t) spt_stack_page_update < USER_STACK &&
	vm_alloc_page(VM_ANON | VM_MARKER_1, spt_stack_page_update, true)){
		spt_stack_page_update += PGSIZE;
	};
	/* pml4에 stack 영역 올려줌 */
	vm_claim_page(stack_top);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
	return false;
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct thread *curr = thread_current ();
	struct supplemental_page_table *spt UNUSED = &curr->spt;
	struct page* page = spt_find_page (spt, addr);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	if (is_kernel_vaddr (addr) && user) return false;
	void *cur_stack_top = pg_round_down (f->rsp);
	if (write && (cur_stack_top - PGSIZE <= addr &&
	      (uintptr_t) addr < USER_STACK)) {
	  vm_stack_growth (addr);
	  return true;
	}
	if (page == NULL) return false;
	if (write && !not_present) return vm_handle_wp (page);
	return vm_do_claim_page (page);
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = spt_find_page (&thread_current () ->spt, va);
	if (page == NULL) return false;
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct thread *curr = thread_current ();
	struct frame *frame = vm_get_frame ();

	/* Set links */
	ASSERT (frame != NULL);
	ASSERT (page != NULL);
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	if (!pml4_set_page (curr -> pml4, page -> va, frame->kva, page -> writable))
		return false;
	return swap_in (page, frame->kva);
}

static uint64_t
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, hash_elem);
return hash_bytes (&p->va, sizeof p->va);
}

static bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, hash_elem);
  const struct page *b = hash_entry (b_, struct page, hash_elem);

  return a->va < b->va;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	struct hash* page_table = malloc(sizeof (struct hash));
	hash_init (page_table, page_hash, page_less, NULL);
	spt -> page_table = page_table;
}

/* Copy supplemental page table from src to dst */
bool supplemental_page_table_copy(struct supplemental_page_table *dst UNUSED,
																	struct supplemental_page_table *src UNUSED)
{
	struct hash_iterator i;
	hash_first(&i, src->page_table);
	while (hash_next(&i))
	{
		struct page *page = hash_entry (hash_cur (&i), struct page, hash_elem);
		/* Handle ANON/FILE page*/
		if (page_get_type(page) == VM_ANON)
		{
			if (!vm_alloc_page(page->operations->type, page->va, page->writable))
				return false;
			struct page *new_page = spt_find_page(&thread_current()->spt, page->va);
			if (!vm_do_claim_page(new_page))
				return false;
			memcpy(new_page->frame->kva, page->frame->kva, PGSIZE);
		}
	}
}

static void
spt_destroy (struct hash_elem *e, void *aux UNUSED){
	struct page *page = hash_entry (e, struct page, hash_elem);
	ASSERT (page != NULL);
	destroy (page);
	free (page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	if (spt -> page_table == NULL) return;
	lock_acquire(&spt_kill_lock);
	hash_destroy(spt->page_table, spt_destroy);
	free(spt->page_table);
	lock_release(&spt_kill_lock);
}
