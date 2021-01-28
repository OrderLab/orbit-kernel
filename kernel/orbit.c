#include <linux/orbit.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/syscalls.h>

typedef void*(*obEntry)(void*);

/* The snapshot and zap part is copied and modified from memory.c */


struct orbit_task *orbit_create_task(void __user *arg,
				unsigned long start, unsigned long end)
{
	struct orbit_task *new_task;

	new_task = kmalloc(sizeof(struct orbit_task), GFP_KERNEL);
	if (new_task == NULL)
		return NULL;

	INIT_LIST_HEAD(&new_task->elem);
	sema_init(&new_task->finish, 0);
	new_task->retval = 0;
	new_task->arg = arg;
	new_task->start = start;
	new_task->start = end;

	return new_task;
}

struct orbit_info *orbit_create_info(void __user **argptr)
{
	struct orbit_info *info;

	info = kmalloc(sizeof(struct orbit_task), GFP_KERNEL);
	if (info == NULL)
		return NULL;

	INIT_LIST_HEAD(&info->task_list);
	sema_init(&info->sem, 0);
	mutex_init(&info->list_lock);
	info->current_task = NULL;
	info->argptr = argptr;

	return info;
}

/* FIXME: Currently we send a task to the orbit, and let the orbit child to
 * create a snapshot actively. When should the snapshot timepoint happen?
 * Should it be right after the orbit call? If so, we may need to wait for the
 * orbit to finish its last task. */

/* FIXME: `start` and `end` should be platform-independent (void __user *)? */

SYSCALL_DEFINE5(orbit_call, int, obid,
		unsigned long, start,
		unsigned long, end,
		obEntry __user, entry_func,	/* this is currently unused */
		void __user *, arg)
{
	struct task_struct *ob;
	struct orbit_info *info;
	struct orbit_task *new_task;
	unsigned long ret;

	if (!(start < end))
		return -EINVAL;

	/* 1. Find the orbit context by obid, currently we only support one
	 * orbit entity per process, thus we will ignore the obid. */
	ob = current->orbit_child;
	info = ob->orbit_info;

	/* 2. Create a orbit task struct and add to the orbit's task queue. */
	new_task = orbit_create_task(arg, start, end);
	if (new_task == NULL)
		return -ENOMEM;

	/* Add task to the queue */
	/* TODO: make killable? */
	mutex_lock(&info->list_lock);
	list_add_tail(&new_task->elem, &info->task_list);
	mutex_unlock(&info->list_lock);
	up(&info->sem);

	/* 3. Wait for the task to finish */
	/* TODO: make killable? */
	down(&new_task->finish);
	ret = new_task->retval;

/* free_task: */
	kfree(new_task);

	return ret;
}

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
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *task;	/* Both old and new task. */
	struct vm_area_struct *parent_vma;

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
		up(&task->finish);
	}

	/* Second half: handle the next task */

	/* 1. Wait for a task to come in */
	/* TODO: make killable? */
	down(&info->sem);
	mutex_lock(&info->list_lock);
	info->current_task = task =
		list_first_entry(&info->task_list, struct orbit_task, elem);
	list_del(info->task_list.next);
	mutex_unlock(&info->list_lock);

	/* 2. Snapshot the page range */
	/* TODO: vma return value error handling */
	parent_vma = find_vma(parent->mm, task->start);
	/* vma_interval_tree_iter_first() */
	/* Currently we assume that the range will only be in one vma */
	if (!(parent_vma->vm_start <= task->start &&
		task->end <= parent_vma->vm_end)) {
		/* TODO: cleanup  */
		panic("orbit error handling unimplemented!");
	}
	/* TODO: Update orbit vma list */
	/* Copy page range */
	update_page_range(ob->mm, parent->mm, parent_vma, task->start, task->end);

	/* 3. Setup the user argument to call entry_func.
	 * Current implementation is that the user runtime library passes
	 * a pointer to the arg (void **) to the orbit_create call.
	 * Upon each orbit_call, the father passes a argument pointer to the
	 * syscall. The kernel will write the pointer to the arg pointer.
	 * TODO: For now we require the argument to be stored in the snapshotted
	 * memory region.
	 */
	put_user(task->arg, info->argptr);

	/* 4. Return to userspace to start checker code */
	return 0;
}
