#ifndef __ORBIT_H__
#define __ORBIT_H__

#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/refcount.h>

/* This struct is part of the task_struct.
 * For now, we only allow at most one orbit for each process.
 * The parent task_struct has a pointer to the child, and the child reuse the
 * same pointer to point to the parent. The is_orbit bit denotes whether the
 * process is an orbit. */
struct orbit_info {
	void __user		**argptr;

	struct semaphore	sem;
	struct mutex		task_lock;
	struct list_head	task_list;	/* orbit_task queue */
	/* TODO: use lockfree list for tasks and atomic for counter */
	unsigned long		taskid_counter;
	/* FIXME: This is a hack to get current running task. Ideally we should
	 * support multiple checker tasks at the same time. */
	struct orbit_task	*current_task;
	/* Pointer to the next task. NULL when queue is empty. This field will
	 * be updated when inserting or popping a task into/from the queue. */
	struct orbit_task	*next_task;
} __randomize_layout;

/* Orbit flags */
#define ORBIT_ASYNC	1

/* This struct is created by  */
struct orbit_task {
	unsigned long		taskid;		/* valid taskid starts from 1 */
	unsigned long		flags;
	struct list_head	elem;
	/* ARC. Value should be list_size(updates).
	 * This is currently only used in ORBIT_ASYNC mode. */
	refcount_t		refcount;
	/* In non-async mode, orbit_call will wait on this semaphore. */
	struct semaphore	finish;

	void __user		*arg;
	unsigned long		retval;
	unsigned long		start, end;	/* Memory range to be snapshotted */

	struct mutex		updates_lock;	/* lock for update list */
	struct semaphore	updates_sem;
	struct list_head	updates;	/* List of updates to be applied */
} __randomize_layout;

#define ORBIT_BUFFER_MAX 4096	/* Maximum buffer size of orbit_update data field */

struct orbit_update_user {
	void __user	*ptr;
	size_t		length;
	char		data[];
};

struct orbit_update {
	struct list_head		elem;
	struct orbit_update_user	userdata;
};

struct orbit_info *orbit_create_info(void __user **argptr);

#endif /* __ORBIT_H__ */
