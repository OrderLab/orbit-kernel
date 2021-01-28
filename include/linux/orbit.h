#ifndef __ORBIT_H__
#define __ORBIT_H__

#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/list.h>

/* This struct is part of the task_struct.
 * For now, we only allow at most one orbit for each process.
 * The parent task_struct has a pointer to the child, and the child reuse the
 * same pointer to point to the parent. The is_orbit bit denotes whether the
 * process is an orbit. */
struct orbit_info {
	struct semaphore	sem;
	void __user		**argptr;
	struct mutex		list_lock;
	struct list_head	task_list;	/* orbit_task queue */
	/* FIXME: This is a hack to get current running task. Ideally we should
	 * support multiple checker tasks at the same time. */	
	struct orbit_task	*current_task;
};

/* This struct is created by  */
struct orbit_task {
	struct list_head	elem;
	void __user		*arg;
	struct semaphore	finish;
	unsigned long		retval;
	unsigned long		start, end;	/* Memory range to be snapshotted */
};

struct orbit_info *orbit_create_info(void __user **argptr);

#endif /* __ORBIT_H__ */
