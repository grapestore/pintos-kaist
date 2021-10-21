/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "filesys/file.h"
#include "userprog/process.h"
#include "threads/vaddr.h"
#include "threads/mmu.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};


/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}



struct mmap_file_info{
	uint64_t mapid;
	uint64_t end;
	struct list_elem elem;
	struct file* file;
	struct list* vme_list;
};

static bool
lazy_load_segment (struct page *page, void *aux) {
	/* TODO: Load the segment from the file */
	/* TODO: This called when the first page fault occurs on address VA. */
	/* TODO: VA is available when calling this function. */
	/* Load the segment from the file */
	/* This called when the first page fault occurs on address VA. */
	/* VA is available when calling this function. */
	struct load_info* li = (struct load_info *) aux;
	if (page == NULL) return false;
	ASSERT(li ->page_read_bytes <=PGSIZE);
	ASSERT(li -> page_zero_bytes <= PGSIZE);
	/* Load this page. */
	if (li -> page_read_bytes > 0) {
		file_seek (li -> file, li -> ofs);
		if (file_read (li -> file, page -> va, li -> page_read_bytes) != (off_t) li -> page_read_bytes) {
			vm_dealloc_page (page);
			free (li);
			return false;
		}
	}
	memset (page -> va + li -> page_read_bytes, 0, li -> page_zero_bytes);
	file_close (li -> file);
	free (li);
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable,
		struct file *file, off_t offset) {
			/* length는 pgsize의 배수여야 한다.*/

			off_t read_ofs = offset;
			void * ori_addr = addr;
			size_t read_bytes = length > file_length(file) ? file_length(file) : length;
    	size_t zero_bytes = PGSIZE - read_bytes;

			while (read_bytes > 0 || zero_bytes > 0){
				size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
				size_t page_zero_bytes = PGSIZE - page_read_bytes;

				struct mmap_info *aux = calloc(sizeof(struct mmap_info),1);
				
				aux->file = file_reopen(file);
				aux->offset = read_ofs;
				aux->read_bytes = page_read_bytes;
				aux->zero_bytes = page_zero_bytes;
				if(!vm_alloc_page_with_initializer (VM_FILE, (void*) ((uint64_t) addr), writable, lazy_load_segment, (void*) aux))
					return;
				read_bytes -= page_read_bytes;
				zero_bytes -= page_zero_bytes;
				read_ofs += page_read_bytes;
				addr += PGSIZE;
			}
			
			struct mmap_file_info* mfi = malloc (sizeof (struct mmap_file_info));
			mfi->mapid = ori_addr;
			mfi->end = (uint64_t) pg_round_down((uint64_t) ori_addr + read_bytes -1);
			//printf("\n\ncheck : %p thread :%s \n\n", mfi->mapid, thread_current()->name);
			list_push_back(&thread_current()->mmap_file_list, &mfi->elem);
			
			return ori_addr;
}

/* Do the munmap */
void
do_munmap (void *addr) {
	
	if (list_empty (&thread_current()->mmap_file_list)) return;
	struct list *mmap_list = &thread_current()->mmap_file_list;
	//printf("\n\nbegin : %p end : %p\n\n", list_begin (&mmap_list), list_end (&mmap_list));
	for (struct list_elem* i = list_begin (mmap_list); i != list_end (mmap_list); i = list_next (i))
	{
		struct mmap_file_info* mfi = list_entry (i, struct mmap_file_info, elem);
		//printf("\n\ncheck : %p thread :%s \n\n", mfi->mapid, thread_current()->name);
		if (mfi -> mapid == (uint64_t) addr){
			for (uint64_t j = (uint64_t)addr; j<= mfi -> end; j += PGSIZE){
				struct page* page = spt_find_page(&thread_current() -> spt, (void*) j);
				spt_remove_page(&thread_current()->spt, page);
			}
			list_remove(&mfi->elem);
			free(mfi);
			return;
		}
	}
}

/* Initialize the file mapped page */
bool
file_map_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	struct file* file = ((struct mmap_info*)page ->uninit.aux)->file;
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
	file_page -> file = file;
	return true;
}