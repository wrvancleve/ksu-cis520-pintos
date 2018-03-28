#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#define USER_VADDR_BOTTOM ((void *) 0x08048000)

/* Our Implementations */
static int current_fd = 1; // Current fd value
struct list open_files; // List of open files
struct lock file_lock; // Lock for files

struct file_descriptor {
  int fd;
  tid_t owner;
  struct file *file;
  struct list_elem elem;
};
/* End Implementations */

static void syscall_handler (struct intr_frame *);
/* Our Implementations */
void halt(void);
void exit(int);
int exec(const char *);
int wait(int);
bool create(const char *, unsigned);
bool remove(const char *);
int open(const char *);
int filesize(int);
int read(int, void *, unsigned);
int write(int, const void *, unsigned);
void seek(int, unsigned);
unsigned tell(int);
void close(int);
struct file_descriptor *get_file(int);
void close_file(int);
void check_pointer(const void*);
void get_args(struct intr_frame *, int *, int);
void check_buffer(void *, unsigned);
int user_to_kernel_pointer(const void *);
/* End Implementations */

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&open_files); // Initialize open files list
  lock_init(&file_lock); // Initialize file lock
}

/*
   Modified By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: System call handler.                              */
static void
syscall_handler (struct intr_frame *f UNUSED)
{
  int args[3]; // Declare arguments array
  check_pointer((const void *) f->esp); // Verify that the pointer is valid
  if (pagedir_get_page(thread_current()->pagedir, (const void *) f->esp) == NULL) exit(ERROR);
  
  switch (*(int*)f->esp)
  {
	case SYS_HALT:
		halt(); // Halt
		break;
		
	case SYS_EXIT:
		get_args(f, &args[0], 1); // Get arguments from the stack
		exit(args[0]); // Exit with argument 1
		break;
		
	case SYS_EXEC:
    get_args(f, &args[0], 1); // Get arguments from the stack
    args[0] = user_to_kernel_pointer((const void *) args[0]); // Get kernel pointer from the provided user pointer
    f->eax = exec((const char *) args[0]);
		break;
		
	case SYS_WAIT:
    get_args(f, &args[0], 1); // Get arguments from the stack
	  f->eax = wait(args[0]); // Wait call
		break;
		
	case SYS_CREATE:
    get_args(f, &args[0], 2); // Get arugments from the stack
    args[0] = user_to_kernel_pointer((const void *) args[0]); // Get kernel pointer from the provided user pointer
    f->eax = create((const char *) args[0], (unsigned) args[1]); // Create call
		break;
		
	case SYS_REMOVE:
    get_args(f, &args[0], 1); // Get arugments from the stack
    args[0] = user_to_kernel_pointer((const void *) args[0]); // Get kernel pointer from the provided user pointer
    f->eax = remove((const char *) args[0]); // Remove call
		break;
		
	case SYS_OPEN:
    get_args(f, &args[0], 1); // Get arguments from the stack
    args[0] = user_to_kernel_pointer((const void *) args[0]); // Get kernel pointer from the provided user pointer
    f->eax = open((const char *) args[0]); // Open call
		break;
		
	case SYS_FILESIZE:
    get_args(f, &args[0], 1); // Get arguemnts from the stack
    f->eax = filesize(args[0]); // Filesize call
		break;
		
	case SYS_READ:
    get_args(f, &args[0], 3); // Get arguments from the stack
    check_buffer((void*)args[1], (unsigned) args[2]); // Verify that the buffer is valid
    args[1] = user_to_kernel_pointer((const void *) args[1]); // Get kernel pointer from the provided user pointer
    f->eax = read(args[0], (void*) args[1], (unsigned) args[2]); // Push the number of bytes that was read to the stack
		break;
		
	case SYS_WRITE:
    get_args(f, &args[0], 3); // Get arguments from the stack
    check_buffer((void*)args[1], (unsigned) args[2]); // Verify that the buffer is valid
    args[1] = user_to_kernel_pointer((const void*) args[1]); // Get kernel pointer from the provided user pointer
    f->eax = write(args[0], (const void*) args[1], (unsigned) args[2]); // Push the number of bytes that was written to the stack 
		break;
		
	case SYS_SEEK:
    get_args(f, &args[0], 2); // Get arguments from the stack
    seek(args[0], (unsigned) args[1]); // Seek call
		break;
		
	case SYS_TELL:
    get_args(f, &args[0], 1); // Get arguments from the stack
    f->eax = tell(args[0]); // Tell call
		break;
		
	case SYS_CLOSE:
    get_args(f, &args[0], 1); // Get arguments from the stack
    close(args[0]); // Close call
		break;
  }
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Halt system call.                                 */
void halt() {
  shutdown_power_off(); // Call shutdown and power off
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Exit system call.                                 */
void exit(int status) {
	struct thread *current = thread_current(); // Get current thread 
  struct thread *parent = thread_get(current->parent_tid); // Get parent thread by thread id from all list
  
  if (parent != NULL) {
    lock_acquire(&parent->child_lock); // Acquire child lock
    current->child->exit = true; // Indicate the child will be exiting
    current->child->status = status; // Indicate the child's exit status
    lock_release(&parent->child_lock); // Release child lock
  }
  
  printf("%s: exit(%d)\n", current->name, status); // Broadcast that an exit has occured to the console
	thread_exit(); // Exit thread
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Exec system call.                                  */
int exec(const char *cmd) {
  struct thread *current = thread_current(); // Get current thread
  current->child_status = NOT_LOADED; // Set child status to not loaded
  int pid = process_execute(cmd); // Execute cmd and get tid 
  while (current->child_status == NOT_LOADED) barrier();
  if (current->child_status == LOAD_FAIL) pid = ERROR; // Set pid to error -1
  return pid;
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Wait system call.                                 */
int wait(int pid) {
  return process_wait(pid); // Call process wait
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Create system call.                                 */
bool create(const char *file, unsigned size) {
  lock_acquire(&file_lock); // Acquire lock
  bool status = filesys_create(file, size); // Create file and save return in status
  lock_release(&file_lock); // Release lock
  return status; // Return satus
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Remove system call.                                 */
bool remove(const char *file) {
  lock_acquire(&file_lock); // Acquire lock
  bool status = filesys_remove(file); // Remove file and save return in status
  lock_release(&file_lock); // Release lock
  return status; // Return satus
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Open system call.                                 */
int open(const char *file) {
  int status = ERROR; // Initialize return status with -1
  lock_acquire(&file_lock); // Acquire lock
  
  struct file *f = filesys_open(file); // Open file
  if (f != NULL) {
    struct file_descriptor *file_des = malloc(sizeof(struct file_descriptor)); // Start file descriptor
    file_des->fd = ++current_fd; // Set file_des' fd to the current fd+1
    file_des->owner = thread_current()->tid; // Set file_des' owner to the current thread
    file_des->file = f; // Set file_des' file to f
    list_push_back(&open_files, &file_des->elem); // Add file_des to open file list
    status = file_des->fd; // Set status as file_des' fd
  }
   
  lock_release(&file_lock); // Release lock
  return status; // Return status
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Filesize system call.                              */
int filesize(int fd) {
  int status = ERROR; // Initialize return status with -1
  lock_acquire(&file_lock); // Acquire lock
  struct file_descriptor *file_des = get_file(fd); // Get file descriptor by fd interger
  if (file_des != NULL) status = file_length(file_des->file); // Call file length and save status return
  lock_release(&file_lock); // Release lock
  return status; // Return status
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Read system call.                                 */
int read(int fd, void * buffer, unsigned size) {
  int bytes = 0; // Initialize bytes return to 0
  
  if (fd == STDOUT_FILENO) bytes = ERROR; // Error set bytes to -1
  else if (fd == STDIN_FILENO) // If the file directory number is equal to standard input
  { 
    uint8_t* buf = (uint8_t *) buffer; // Convert buffer to int pointer
    for (unsigned i = 0; i < size; i++) buf[i] = input_getc(); // Get the input of each character as a int from the console
    bytes = size; // Set bytes to the number of bytes read
  }
  else {
    lock_acquire(&file_lock); // Get lock
    struct file_descriptor *file_des = get_file(fd); // Get the file of the file directory to read from
    if (file_des != NULL) bytes = file_read(file_des->file, buffer, size); // Reads the file and saves the number of bytes read
    lock_release(&file_lock); // Release lock
  }
  
  return bytes; // Return number of bytes read
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Write system call.                                */
int write(int fd, const void * buf, unsigned size) {
  int bytes = 0; // Initialize bytes return to 0
  
  if (fd == STDIN_FILENO) bytes = ERROR; // Error set bytes to -1
  else if (fd == STDOUT_FILENO) // If the file directory number is equal to standard output
  {
    putbuf(buf, size); // Write the whole buffer to the console
    bytes = size; // Return the number of bytes written
  }
  else {
    lock_acquire(&file_lock); // Get lock
    struct file_descriptor *file_des = get_file(fd); // Get the file of the file directory to write to
    if (file_des != NULL ) bytes = file_write(file_des->file, buf, size); // Write to the file and save number of bytes written
    lock_release(&file_lock); // Release lock
  }
  
  return bytes; // Return the number of bytes written
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Seek system call.                                */
void seek(int fd, unsigned pos) {
  lock_acquire(&file_lock); // Acquire lock
  struct file_descriptor *file_des = get_file(fd); // Get file descriptor by fd interger
  if (file_des != NULL) file_seek(file_des->file, pos); // Seek for the file at the position
  lock_release(&file_lock); // Release lock
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Tell system call.                                 */
unsigned tell(int fd) {
  int status = 0; // Initialize return status to 0
  lock_acquire(&file_lock); // Acquire lock
  struct file_descriptor *file_des = get_file(fd); // Get file descriptor by fd interger
  if (file_des != NULL) status = file_tell(file_des->file); // Call tell and save return status
  lock_release(&file_lock); // Release lock
  return status; // Return status
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Close system call.                                */
void close(int fd) {
  lock_acquire(&file_lock); // Acquire lock
  struct file_descriptor *file_des = get_file(fd); // Get file descriptor by fd interger
  if (file_des != NULL && file_des->owner == thread_current()->tid) close_file(fd); // Close file
  lock_release(&file_lock); // Release lock
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Add child process to children list.                */
struct child_process *add_child(int pid) {
  struct child_process *child = malloc(sizeof(struct child_process)); // Allocate memory for child_process
  child->pid = pid; // Set child's pid
  child->wait = false; // Set child isn't waiting
  child->exit = false; // Set child isn't exiting
  list_push_back(&thread_current()->children, &child->elem); // Add child to children list
  return child;
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Gets child process from children list.             */
struct child_process *get_child(int pid) {
  struct thread *current = thread_current(); // Get current thread
  for (struct list_elem *e = list_begin(&current->children); e != list_end(&current->children); e = list_next(e)) {
    struct child_process *child = list_entry(e, struct child_process, elem); // Get child process from element
    if (child->pid == pid) return child; // Found child
  }
  return NULL; // Child wasn't found
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Removes a child process from children list.        */
void remove_child(struct child_process *child) {
  list_remove(&child->elem); // Remove from list
  free(child); // Free memory
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Remove all child processes from children list.     */
void remove_children() {
  struct thread *current = thread_current(); // Get current thread  
  struct list_elem *e = list_begin(&current->children);
  
  while(e != list_end(&current->children)) {
    struct list_elem *next = list_next(e); // Get next child in list
    struct child_process *child = list_entry(e, struct child_process, elem); // Get child process from list element
    list_remove(&child->elem); // Remove child from list
    free(child); // Free memory
    e = next; // Set element to next element
  }
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Gets file description from open file list by fd integer. */
struct file_descriptor *get_file(int fd) {
  for (struct list_elem *e = list_begin(&open_files); e != list_end(&open_files); e = list_next(e)) {
    struct file_descriptor *file_des = list_entry(e, struct file_descriptor, elem); // Get file descriptor from open file list
    if (file_des->fd == fd) return file_des; // Found file
  }
  return NULL; // File wasn't found
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Closes file by fd integer.                        */
void close_file(int fd) {
  struct list_elem *e = list_begin(&open_files); // Get beginning of open files list
  while (e != list_end(&open_files)) {
    struct list_elem *next = list_next(e); // Get next element in the list
    struct file_descriptor *file_des = list_entry(e, struct file_descriptor, elem); // Get file descriptor from open file list
    if (file_des->fd == fd || (file_des->owner == thread_current()->tid && fd == ALL)) {
      list_remove(e); // Remove from open files list
      file_close(file_des->file); // Close file
      free(file_des); // Free memory
      if (fd != ALL)return; // Return if not closing all
    }
    e = next; // Set e to next
  }
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Determines whether a pointer is valid or not.     */
void check_pointer(const void *vaddr) {
	if (!is_user_vaddr(vaddr) || vaddr < USER_VADDR_BOTTOM) exit(ERROR); // If vaddr is null or invalid exit with status -1
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
	   https://github.com/ryantimwilson/Pintos-Project-2
   Description: Fills args array with valid arguments from the stack. */
void get_args(struct intr_frame *f, int *args, int n) {
  int *ptr;
	for (int i = 0; i < n; i++) // Move through number of arguments
  {
		ptr = (int *) f->esp + i + 1; // Get the pointer of argument i+1
		check_pointer((const void *) ptr); // Verify pointer of argument i+1
		args[i] = *ptr; // Save argument i+1
	}
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
		 https://github.com/ryantimwilson/Pintos-Project-2
   Description: Determines whether a buffer is valid or not.      */
void check_buffer(void* buffer, unsigned size) {
  char* buf = (char*) buffer; // Cast buffer to a char pointer buffer
  for(unsigned i = 0; i < size; i++) // Move through the entire buffer
  {
    check_pointer((const void *) buf); // Check whether the pointer is valid
    buf++; // Move to next location in buffer
  }
}

/*
   Added By: William Van Cleve, Shawn Kirby and Connor McElroy
   Changes Inspired By: https://github.com/Waqee/Pintos-Project-2
     https://github.com/codyjack/OS-pintos
	   https://github.com/ryantimwilson/Pintos-Project-2
   Description: Gets the kernel pointer of a user provided pointer. */
int user_to_kernel_pointer(const void *vaddr) {
  check_pointer(vaddr); // Check that the virtual address is valid
  void *pointer = pagedir_get_page(thread_current()->pagedir, vaddr); // Get the page of the virtual address
  if(!pointer) exit(ERROR); // If pointer is null then exit with error code -1
  return (int) pointer; // Return pointer as a int
}