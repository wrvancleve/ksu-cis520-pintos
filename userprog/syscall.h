#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "threads/synch.h"
#include <stdbool.h>

#define ALL -1
#define ERROR -1
#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL -1

struct child_process {
  int pid; // Thread id of the child
  bool exit; // Indicates whether the child is exiting or not
  bool wait; // Indicates whether the child has been waiting or not
  int status; // Indicates the exit status of the child
  struct list_elem elem; // List element of the child process
};

struct child_process* add_child (int pid);
struct child_process* get_child (int pid);
void remove_child (struct child_process *cp);
void remove_children (void);

void syscall_init (void);

#endif /* userprog/syscall.h */
