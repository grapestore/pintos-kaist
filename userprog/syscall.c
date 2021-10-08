#include "userprog/syscall.h"
#include "userprog/process.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/*              system call by inkyu            */
void halt(void);
void exit(int status);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open (const char *file);
int filesize(int fd);
int exec(const *cmd_line);
int read (int fd , void *buffer, unsigned size);

/*              system call need func by inkyu            */
int add_file_to_fdt(struct file *file);
static struct file *find_file_by_fd(int fd);
void check_address(const uint64_t *uaddr);
void remove_file_from_fdt(int fd);

const int STDIN = 1;
const int STDOUT = 2;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.
	switch (f->R.rax)
	{
	case SYS_HALT:
		halt();
		break;
	case SYS_EXIT:
		exit(f->R.rdi);
		break;
	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;
	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;
	case SYS_CLOSE:
		close(f->R.rdi);
		break;
	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;
	case SYS_EXEC:
		f->R.rax = exec(f->R.rdi);
		break;
	case SYS_READ:

		break;
	
	default:
		break;
	}
}

void halt(void)
{
	power_off();
}

void exit(int status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;

	printf("%s: exit(%d)\n", thread_name(), status); // Process Termination Message
	thread_exit();
}

bool create(const char *file, unsigned initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file)
{
	check_address(file);
	return filesys_remove(file);
}

int
open (const char *file) {
	check_address(file);
	struct file *fileobj = filesys_open(file);

	if (fileobj == NULL)
		return -1;
	
	int fd = add_file_to_fdt(fileobj);


	if(fd == -1)
		return file_close(fileobj);

	return fd;
}

void close(int fd)
{
	/*       fd를이용하여 file 받음 by inky           */
	struct file *objfile = find_file_by_fd(fd);
	struct thread *cur = thread_current();

	if(objfile == NULL)
		return -1;

	if (fd == 0 || objfile == STDIN)
	{
		cur->stdin_count--;
	}
	else if (fd == 1 || objfile == STDOUT)
	{
		cur->stdout_count--;
	}

	
/*      table 에서 삭제           */
	remove_file_from_fdt(fd);

	file_close(objfile);

	return;
}

int add_file_to_fdt(struct file *file)
{
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdTable;

	//파일 개수 및 새로 열 파일의 fd값 raise
	while(cur->fdIdx<FDCOUNT_LIMIT && fdt[cur->fdIdx])
	{
		cur->fdIdx++;
	}

	// fdt full limit 512개
	if(cur->fdIdx >= FDCOUNT_LIMIT)
		return -1;
	
	fdt[cur->fdIdx] = file;
	return cur->fdIdx;
}

int filesize(int fd)
{
	struct file *fileobj = find_file_by_fd(fd);
	if(fileobj == NULL)
		return -1;
	return file_length(fileobj);
}

static struct file *find_file_by_fd(int fd)
{
	struct thread *cur = thread_current();
	if(fd<0 || fd>=FDCOUNT_LIMIT)
		return NULL;

	return cur->fdTable[fd];
}

void check_address(const uint64_t *uaddr)
{
	struct thread *cur = thread_current();
	if (uaddr == NULL || !(is_user_vaddr(uaddr)) || pml4_get_page(cur->pml4, uaddr) == NULL)
	{
		exit(-1);
	}
}

int exec(const *cmd_line)
{
	check_address(cmd_line);
	char *file_name[30];
	memcpy(file_name, cmd_line, strlen(cmd_line) + 1);
	if(process_exec(file_name) == -1)
		return -1;

	NOT_REACHED();
	return 0;
}

void remove_file_from_fdt(int fd)
{
	struct thread *cur = thread_current();

	// Error - invalid fd
	if (fd < 0 || fd >= FDCOUNT_LIMIT)
		return;

	cur->fdTable[fd] = NULL;
}

int read (int fd , void *buffer, unsigned size)
{
	check_address(buffer);
	struct file *fileobj = find_file_by_fd(fd);
	if(fileobj == NULL)
		return -1;
	
	if(fd == 0)
	{
		buffer = input_getc();
	}
	else if(fd == 1){
		return -1;
	}
	else{
		return file_read(fileobj, buffer, size);
	}
}