#ifndef _ORBIT_INTERNAL_H_
#define _ORBIT_INTERNAL_H_

#include <linux/orbit.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/refcount.h>

/* Orbit flags */
#define ORBIT_ASYNC		(1<<0) /* Whether the call is async */
#define ORBIT_NORETVAL		(1<<1) /* Whether we want the return value.
					This option is ignored in async. */
#define ORBIT_CANCELLABLE	(1<<2)
#define ORBIT_SKIP_SAME_ARG	(1<<3)
#define ORBIT_SKIP_ANY		(1<<4)
#define ORBIT_CANCEL_SAME_ARG	(1<<5)
#define ORBIT_CANCEL_ANY	(1<<6)
/* #define ORBIT_CANCEL_ALL	(1<<7) */

/* Orbit name max length */
#define ORBIT_NAME_LEN 24

struct orbit_info {
	void __user *argbuf;
	orbit_entry __user *funcptr;

	struct semaphore sem;
	struct semaphore exit_sem;

	spinlock_t task_lock;
	/* The following fields are protected by `task_lock` */
	bool snap_active; /* One thread is active in direct snapshot */
	struct list_head task_list; /* orbit_task queue */
	/* TODO: use lockfree list for tasks and atomic for counter */
	unsigned long taskid_counter;
	/* FIXME: This is a hack to get current running task. Ideally we should
	 * support multiple checker tasks at the same time. */
	struct orbit_task *current_task;
	/* Pointer to the next task.
	 * This is used because finished task still needs to present in the
	 * task list, otherwise recv side won't be able to get the result.
	 * So we cannot directly use the list in the exact same way as a queue.
	 * NULL when queue is empty. This field will be updated when inserting
	 * or popping a task into/from the queue. Orbit side will skip
	 * cancelled tasks. */
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

	/* The following three fields are protected by `task_lock` */
	struct list_head elem;
	refcount_t refcount; /* ARC. */
	bool cancelled;

	/* In non-async mode, orbit_call will wait on this semaphore. */
	struct semaphore finish;

	orbit_entry func;
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

static inline void *task_argbuf(struct orbit_task *task)
{
	return task->pools + task->npool;
}

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

enum orbit_cancel_kind { ORBIT_CANCEL_ARGS, ORBIT_CANCEL_TASKID,
			 ORBIT_CANCEL_KIND_ANY, };
/* We have a naming conflict on ORBIT_CANCEL_KIND_ANY and ORBIT_CANCEL_ANY. */

struct orbit_cancel_user_args {
	obid_t gobid;
	enum orbit_cancel_kind kind;
	union {
		struct {
			void __user *arg;
			size_t argsize;
		};
		unsigned long taskid;
	};
};

struct orbit_cancel_args {
	struct orbit_info *info;
	enum orbit_cancel_kind kind;
	union {
		struct {
			void *arg;
			size_t argsize;
		};
		unsigned long taskid;
	};
};

#endif /* _ORBIT_INTERNAL_H_ */
