#include <linux/orbit.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

typedef void*(*obEntry)(void*);

/* The snapshot and zap part is copied and modified from memory.c */

#define DBG 1

#define printd if(DBG)printk

#define whatis(x) printd(#x " is %lu\n", x)

#if DBG == 1
	#define internalreturn long __attribute__((optimize("O0")))
#else
	#define internalreturn static inline long __attribute__((always_inline))
#endif

struct orbit_task *orbit_create_task(unsigned long flags, void __user *arg,
				unsigned long start, unsigned long end)
{
	struct orbit_task *new_task;

	new_task = kmalloc(sizeof(*new_task), GFP_KERNEL);
	if (new_task == NULL)
		return NULL;

	INIT_LIST_HEAD(&new_task->elem);
	INIT_LIST_HEAD(&new_task->updates);
	sema_init(&new_task->updates_sem, 0);
	mutex_init(&new_task->updates_lock);
	//if (flags & ORBIT_ASYNC)
		refcount_set(&new_task->refcount, 0);
	//else
		sema_init(&new_task->finish, 0);
	new_task->retval = 0;
	new_task->arg = arg;
	new_task->start = start;
	new_task->end = end;
	new_task->taskid = 0;	/* taskid will be allocated later */
	new_task->flags = flags;

	return new_task;
}

struct orbit_info *orbit_create_info(void __user **argptr)
{
	struct orbit_info *info;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL)
		return NULL;

	INIT_LIST_HEAD(&info->task_list);
	sema_init(&info->sem, 0);
	mutex_init(&info->task_lock);
	info->current_task = info->next_task = NULL;
	info->argptr = argptr;
	info->taskid_counter = 0;	/* valid taskid starts from 1 */

	return info;
}

/* FIXME: Currently we send a task to the orbit, and let the orbit child to
 * create a snapshot actively. When should the snapshot timepoint happen?
 * Should it be right after the orbit call? If so, we may need to wait for the
 * orbit to finish its last task. */

/* FIXME: `start` and `end` should be platform-independent (void __user *)? */

/* Return value: In normal mode, this call returns the checker call return
	 value. When the ORBIT_ASYNC flag is set, this returns a taskid integer. */
internalreturn orbit_call_internal(
	unsigned long flags, unsigned long obid,
	unsigned long start, unsigned long end,
	obEntry __user entry_func, void __user * arg);

SYSCALL_DEFINE6(orbit_call, unsigned long, flags,
		unsigned long, obid,
		unsigned long, start,
		unsigned long, end,
		obEntry __user, entry_func,	/* this is currently unused */
		void __user *, arg)
{
	return orbit_call_internal(flags, obid, start, end, entry_func, arg);
}

internalreturn orbit_call_internal(
	unsigned long flags, unsigned long obid,
	unsigned long start, unsigned long end,
	obEntry __user entry_func, void __user * arg)
{
	struct task_struct *ob;
	struct orbit_info *info;
	struct orbit_task *new_task;
	unsigned long ret;

	if (!(start < end))
		return -EINVAL;

	/* 1. Find the orbit context by obid, currently we only support one
	 * orbit entity per process, thus we will ignore the obid. */
	ob = current->group_leader->orbit_child;
	info = ob->orbit_info;

	/* 2. Create a orbit task struct and add to the orbit's task queue. */
	new_task = orbit_create_task(flags, arg, start, end);
	if (new_task == NULL)
		return -ENOMEM;

	printk("arg = %p, new_task->arg = %p\n", arg, new_task->arg);

	/* Add task to the queue */
	/* TODO: make killable? */
	mutex_lock(&info->task_lock);
	/* Allocate taskid; valid taskid starts from 1 */
	/* TODO: will this overflow? */
	new_task->taskid = ++info->taskid_counter;
	list_add_tail(&new_task->elem, &info->task_list);
	if (info->next_task == NULL)
		info->next_task = new_task;
	mutex_unlock(&info->task_lock);
	up(&info->sem);

	/* 3. Return from main in async mode, */
	if (flags & ORBIT_ASYNC)
		return new_task->taskid;
	/* or wait for the task to finish */
	down(&new_task->finish);	/* TODO: make killable? */
	ret = new_task->retval;

/* free_task: */
	kfree(new_task);

	return ret;
}

struct orbit_update *orbit_create_update(size_t length)
{
	struct orbit_update *new_update;

	new_update = kmalloc(sizeof(struct orbit_update) + length, GFP_KERNEL);
	if (new_update == NULL)
		return NULL;
	INIT_LIST_HEAD(&new_update->elem);

	return new_update;
}

/* Return value: 0 for success, other value for failure */
internalreturn orbit_send_internal(
	const struct orbit_update_user __user * update);

SYSCALL_DEFINE1(orbit_send, const struct orbit_update_user __user *, update)
{
	return orbit_send_internal(update);
}

internalreturn orbit_send_internal(
	const struct orbit_update_user __user * update)
{
	struct orbit_update *new_update;
	unsigned long length;
	struct orbit_task *current_task;

	if (!current->is_orbit)
		return -EINVAL;

	/* TODO: check pointer validity */
	current_task = current->orbit_info->current_task;

	/* This syscall is only available for async mode tasks. */
	if (!(current_task->flags & ORBIT_ASYNC))
		return -EINVAL;

	/* TODO: check validity of get_user() */
	get_user(length, &update->length);

	/* TODO: optimization: write directly to the waiting thread */
	new_update = orbit_create_update(length);
	if (new_update == NULL)
		return -ENOMEM;

	/* TODO: check return value of copy */

#if DBG
	memcpy(&new_update->userdata, update,
			sizeof(struct orbit_update_user) + length);
#else
	copy_from_user(&new_update->userdata, update,
			sizeof(struct orbit_update_user) + length);
#endif

	mutex_lock(&current_task->updates_lock);
	refcount_inc(&current_task->refcount);
	list_add_tail(&new_update->elem, &current_task->updates);
	mutex_unlock(&current_task->updates_lock);
	up(&current_task->updates_sem);

	return 0;
}

/* Return value: 0 for success, other value for failure */
internalreturn orbit_recv_internal(unsigned long obid,
	unsigned long taskid, struct orbit_update_user __user *update_user);

SYSCALL_DEFINE3(orbit_recv, unsigned long, obid,
		unsigned long, taskid,
		struct orbit_update_user __user *, update_user)
{
	return orbit_recv_internal(obid, taskid, update_user);
}

internalreturn orbit_recv_internal(unsigned long obid,
	unsigned long taskid, struct orbit_update_user __user *update_user)
{
	/* TODO: allow multiple orbit */
	/* TODO: check pointer validity */
	struct orbit_info *info = current->group_leader->orbit_child->orbit_info;
	struct orbit_task *task;
	struct orbit_update *update;
	struct list_head *iter;
	int found = 0;

	/* TODO: maybe use rbtree along with the list? */
	mutex_lock(&info->task_lock);
	list_for_each(iter, &info->task_list) {
		task = list_entry(iter, struct orbit_task, elem);
		if (task->taskid == taskid) {
			found = 1;
			break;
		}
	}
	mutex_unlock(&info->task_lock);

	if (!found) {
		printk("taskid %lu not found", taskid);
		return -EINVAL;
	}

	/* This syscall is only available for async mode tasks. */
	if (!(task->flags & ORBIT_ASYNC))
		return -EINVAL;

	/* Now get one of the updates */
	/* FIXME: wake up this */
	down(&task->updates_sem);
	mutex_lock(&task->updates_lock);
	if (unlikely(list_empty(&task->updates))) {
		mutex_unlock(&task->updates_lock);
		return -EIDRM;	/* End of message list. */
	}
	update = list_first_entry(&task->updates, struct orbit_update, elem);
	list_del(&update->elem);
	mutex_unlock(&task->updates_lock);

	/* TODO: check return value of copy */
#if DBG
	memcpy(update_user, &update->userdata,
		sizeof(struct orbit_update_user) + update->userdata.length);
#else
	copy_to_user(update_user, &update->userdata,
		sizeof(struct orbit_update_user) + update->userdata.length);
#endif

	kfree(update);

	/* ARC free task object */
	if (refcount_dec_and_test(&task->refcount) &&
		down_trylock(&task->finish) == 0) {
		list_del(&task->elem);
		kfree(task);
	}

	return 0;
}

internalreturn orbit_return_internal(unsigned long retval);

/* This function has two halves:
 * 1) The first half return the result of the last task.
 *
 * 2) The second half handles the next task.
 *    The function first waits on the orbit task queue to get the next task.
 *    It then sets up the running environment (snapshotting & setting
 *    argument pointer) and return from syscall to start running checker code.
 *    The userspace runtime will trigger this syscall again when the checker
 *    has finished running.
 */
SYSCALL_DEFINE1(orbit_return, unsigned long, retval)
{
	return orbit_return_internal(retval);
}

internalreturn orbit_return_internal(unsigned long retval)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *task;	/* Both old and new task. */
	struct vm_area_struct *parent_vma;

	if (!current->is_orbit)
		return -EINVAL;

	ob = current;
	parent = ob->orbit_child;	/* Currntly orbit_child in orbit is
					 * reused as a pointer to parent. */
	info = ob->orbit_info;

	/* First half: return value to parent */
	task = info->current_task;
	/* Current task can be NULL: in the current implementation, the orbit
	 * does not run any checker code before the first entrance to
	 * orbit_return. */
	if (task != NULL) {
		task->retval = retval;

		mutex_lock(&info->task_lock);

		info->next_task = list_is_last(&task->elem, &info->task_list) ?
					NULL : list_next_entry(task, elem);

		/* In async mode, dec refcount and try to cleanup.
		 * Orbit_recv function will also try to cleanup. */
		if (task->flags & ORBIT_ASYNC) {
			up(&task->finish);
			if (refcount_read(&task->refcount) == 0 &&
				down_trylock(&task->finish) == 0) {
				list_del(&task->elem);
				kfree(task);
			}
		} else {
			/* Otherwise, orbit_call will wait for down(). */
			list_del(&task->elem);
			up(&task->finish);
		}

		mutex_unlock(&info->task_lock);
	}

	/* Second half: handle the next task */

	/* 1. Wait for a task to come in */
	/* TODO: make killable? */
	down(&info->sem);
	mutex_lock(&info->task_lock);
	info->current_task = task = info->next_task;
	info->next_task = list_is_last(&task->elem, &info->task_list) ?
					NULL : list_next_entry(task, elem);
	mutex_unlock(&info->task_lock);

	/* 2. Snapshot the page range */
	/* TODO: vma return value error handling */
	parent_vma = find_vma(parent->mm, task->start);
	/* vma_interval_tree_iter_first() */
	/* Currently we assume that the range will only be in one vma */
	whatis(parent_vma->vm_start);
	whatis(parent_vma->vm_end);
	whatis(task->start);
	whatis(task->end);

	if (!(parent_vma->vm_start <= task->start &&
		task->end <= parent_vma->vm_end)) {
		/* TODO: cleanup  */
		panic("orbit error handling unimplemented!");
	}
	/* TODO: Update orbit vma list */
	/* Copy page range */
#if DBG
	update_page_range(ob->mm, parent->mm, parent_vma, task->start, task->end,
		ORBIT_UPDATE_SNAPSHOT);
#else
	copy_page_range(ob->mm, parent->mm, parent_vma);
#endif

	/* 3. Setup the user argument to call entry_func.
	 * Current implementation is that the user runtime library passes
	 * a pointer to the arg (void **) to the orbit_create call.
	 * Upon each orbit_call, the father passes a argument pointer to the
	 * syscall. The kernel will write the pointer to the arg pointer.
	 * TODO: For now we require the argument to be stored in the snapshotted
	 * memory region.
	 */
	printk("task->arg = %p, info->argptr = %p\n", task->arg, info->argptr);
	put_user(task->arg, info->argptr);

	/* 4. Return to userspace to start checker code */
	return 0;
}

/* Commit the changes made in the orbit.
 * This is a page-level granularity update.
 * This will automatically find the dirty pages and update back to main program. */
internalreturn do_orbit_commit(void)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *task;	/* Both old and new task. */
	struct vm_area_struct *ob_vma;
	int ret;

	if (!current->is_orbit)
		return -EINVAL;

	ob = current;
	parent = ob->orbit_child;	/* Currntly orbit_child in orbit is
					 * reused as a pointer to parent. */
	info = ob->orbit_info;

	task = info->current_task;

	ob_vma = find_vma(ob->mm, task->start);
	ret = update_page_range(parent->mm, ob->mm, ob_vma, task->start, task->end,
		ORBIT_UPDATE_DIRTY);

	return ret;
}

SYSCALL_DEFINE0(orbit_commit)
{
	return do_orbit_commit();
}

/* Encoded orbit updates and operations. */
struct orbit_scratch {
	void *ptr;
	size_t cursor;
	size_t size_limit;
	size_t count;	/* Number of elements */
};

struct orbit_update_v {
	struct list_head		elem;
	struct orbit_scratch		userdata;
};

struct orbit_update_v *orbit_create_update_v(void)
{
	struct orbit_update_v *new_update;

	new_update = kmalloc(sizeof(struct orbit_update_v), GFP_KERNEL);
	if (new_update == NULL)
		return NULL;
	INIT_LIST_HEAD(&new_update->elem);

	return new_update;
}

internalreturn do_orbit_sendv(struct orbit_scratch __user *s)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *current_task;	/* Both old and new task. */
	struct vm_area_struct *ob_vma;
	int ret = 0;
	struct orbit_update_v *new_update;

	if (!current->is_orbit)
		return -EINVAL;

	ob = current;
	parent = ob->orbit_child;	/* Currntly orbit_child in orbit is
					 * reused as a pointer to parent. */
	info = ob->orbit_info;

	current_task = info->current_task;

	/* This syscall is only available for async mode tasks. */
	if (!(current_task->flags & ORBIT_ASYNC))
		return -EINVAL;

	new_update = orbit_create_update_v();
	if (new_update == NULL)
		return -ENOMEM;

	/* TODO: check return value of copy */

#if DBG
	memcpy(&new_update->userdata, s, sizeof(struct orbit_scratch));
#else
	copy_from_user(&new_update->userdata, s, sizeof(struct orbit_scratch));
#endif

	unsigned long scratch_start = (unsigned long)new_update->userdata.ptr;
	unsigned long scratch_end = scratch_start + new_update->userdata.size_limit;
	/*unsigned long scratch_end = scratch_start + new_update->userdata.cursor;*/

	ob_vma = find_vma(ob->mm, scratch_start);
	ret = update_page_range(parent->mm, ob->mm, ob_vma, scratch_start, scratch_end,
		ORBIT_UPDATE_SNAPSHOT);

	mutex_lock(&current_task->updates_lock);
	refcount_inc(&current_task->refcount);
	list_add_tail(&new_update->elem, &current_task->updates);
	mutex_unlock(&current_task->updates_lock);
	up(&current_task->updates_sem);

	return ret;
}

SYSCALL_DEFINE1(orbit_sendv, struct orbit_scratch __user *, s)
{
	return do_orbit_sendv(s);
}

internalreturn do_orbit_recvv(struct orbit_scratch __user *s, unsigned long taskid)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *task;	/* Both old and new task. */
	int ret = 0;
	struct orbit_update_v *update;
	struct list_head *iter;
	int found = 0;

	parent = current->group_leader;
	ob = parent->orbit_child;

	info = ob->orbit_info;

	task = info->current_task;

	/* TODO: maybe use rbtree along with the list? */
	mutex_lock(&info->task_lock);
	list_for_each(iter, &info->task_list) {
		task = list_entry(iter, struct orbit_task, elem);
		if (task->taskid == taskid) {
			found = 1;
			break;
		}
	}
	mutex_unlock(&info->task_lock);

	if (!found) {
		printk("taskid %lu not found", taskid);
		return -EINVAL;
	}

	/* This syscall is only available for async mode tasks. */
	if (!(task->flags & ORBIT_ASYNC))
		return -EINVAL;

	/* Now get one of the updates */
	/* FIXME: wake up this */
	down(&task->updates_sem);
	mutex_lock(&task->updates_lock);
	if (unlikely(list_empty(&task->updates))) {
		mutex_unlock(&task->updates_lock);
		return -EIDRM;	/* End of message list. */
	}
	update = list_first_entry(&task->updates, struct orbit_update_v, elem);
	list_del(&update->elem);
	mutex_unlock(&task->updates_lock);

	/* TODO: check return value of copy */
#if DBG
	memcpy(s, &update->userdata, sizeof(struct orbit_scratch));
#else
	copy_to_user(s, &update->userdata, sizeof(struct orbit_scratch));
#endif

	kfree(update);

	/* ARC free task object */
	if (refcount_dec_and_test(&task->refcount) &&
		down_trylock(&task->finish) == 0) {
		list_del(&task->elem);
		kfree(task);
	}

	return ret;
}

SYSCALL_DEFINE2(orbit_recvv, struct orbit_scratch __user *, s, unsigned long, taskid)
{
	return do_orbit_recvv(s, taskid);
}
