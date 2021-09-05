#ifndef _ORBIT_INTERNAL_H_
#define _ORBIT_INTERNAL_H_

#include <linux/orbit.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/refcount.h>

/* Orbit name max length */
#define ORBIT_NAME_LEN 24

struct orbit_info {
	void __user *argbuf;
	orbit_entry __user *funcptr;

	struct semaphore sem;
	struct semaphore exit_sem;
	struct mutex task_lock;
	struct list_head task_list; /* orbit_task queue */
	/* TODO: use lockfree list for tasks and atomic for counter */
	unsigned long taskid_counter;
	/* FIXME: This is a hack to get current running task. Ideally we should
	 * support multiple checker tasks at the same time. */
	struct orbit_task *current_task;
	/* Pointer to the next task. NULL when queue is empty. This field will
	 * be updated when inserting or popping a task into/from the queue. */
	struct orbit_task *next_task;

	pid_t mpid; /* PID of the attached main program */
	pid_t gobid; /* PID of this orbit task, globally unique */
	obid_t lobid; /* Orbit id, starting from 1. It is locally unique
                     to the main program.*/
	enum orbit_state state; /* state of orbit */
	char name[ORBIT_NAME_LEN]; /* Name of orbit */
};

/* Duplicated struct definition, should be eventually moved to mm.h */
struct vma_snapshot {
	size_t count;
	size_t head, tail; /* Cursor in the first and last snap_block */
	struct list_head list;
};

struct orbit_pool_snapshot {
	unsigned long start, end;
	enum orbit_pool_mode mode;
	struct vma_snapshot snapshot;
	char *data;
};

struct orbit_task {
	unsigned long taskid; /* valid taskid starts from 1 */
	unsigned long flags;
	struct list_head elem;
	/* ARC. Value should be list_size(updates).
	 * This is currently only used in ORBIT_ASYNC mode. */
	refcount_t refcount;
	/* In non-async mode, orbit_call will wait on this semaphore. */
	struct semaphore finish;

	orbit_entry func;
	void __user *arg;
	size_t argsize;
	/* Return value to syscall (non-negative are successful return value,
	 * negative are error codes) */
	long retval;

	struct mutex updates_lock; /* lock for update list */
	struct semaphore updates_sem;
	/* List of updates to be applied
	 * FIXME: Currently this is shared between update and update_v */
	struct list_head updates;

	/* Memory ranges snapshotted. Variable-sized struct. */
	size_t npool;
	struct orbit_pool_snapshot pools[];

	/* Extra field: char arg_data[] starting at (char*)(pools + npool),
	 * see orbit_create_task. */
};

/* FIXME: `start` and `end` should be platform-independent (void __user *)? */
struct orbit_pool_range {
	unsigned long start;
	unsigned long end;
	enum orbit_pool_mode mode;
};

struct orbit_call_args {
	unsigned long flags;
	obid_t gobid;
	size_t npool;
	struct orbit_pool_range __user *pools;
	orbit_entry func;
	void __user *arg;
	size_t argsize;
};

#endif /* _ORBIT_INTERNAL_H_ */
