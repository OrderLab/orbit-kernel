#include <linux/orbit.h>
#include <linux/orbit_internal.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/oom.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/list.h>
#include <linux/refcount.h>
/* For snapshot_share */
#include <linux/security.h>
#include <linux/hugetlb.h>
#include <linux/mempolicy.h>
#include <linux/rmap.h>
#include <linux/userfaultfd_k.h>
#include <linux/signal.h>
#include <linux/rwlock_types.h>
#include <linux/jiffies.h>

#define PREFIX "orbit: "

// change to #define for enabling more debug info just for this module
#undef DEBUG_ORBIT
#undef DEBUG_COPY_MEMCPY

#ifdef DEBUG_ORBIT
#define orb_dbg(fmt, ...)                                                      \
	do {                                                                   \
		printk(KERN_DEBUG PREFIX fmt, ##__VA_ARGS__);                  \
	} while (0)
#else
#define orb_dbg(fmt, ...)                                                      \
	do {                                                                   \
	} while (0)
#endif

#define whatis(x) orb_dbg(#x " is %lu\n", x)

#define internalreturn static long /* __attribute__((always_inline)) */

/* Orbit flags */
#define ORBIT_ASYNC 1 /* Whether the call is async */
#define ORBIT_NORETVAL 2 /* Whether we want the return value.
			    This option is ignored in async. */

#define ARG_SIZE_MAX 1024

__cacheline_aligned DEFINE_RWLOCK(orbitlist_lock);

void snap_init(struct vma_snapshot *snap);
void snap_destroy(struct vma_snapshot *snap);

static struct orbit_task *
orbit_create_task(unsigned long flags, orbit_entry func, void __user *arg,
		  size_t argsize, size_t npool,
		  struct orbit_pool_range __user *pools)
{
	struct orbit_task *new_task;
	size_t i;

	new_task = kmalloc(sizeof(*new_task) + argsize +
				   npool * sizeof(struct orbit_pool_snapshot),
			   GFP_KERNEL);
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
	/* process error by default, orbit_return will overwrite this */
	new_task->retval = -ESRCH;
	new_task->func = func;
	new_task->arg = arg;
	new_task->argsize = argsize;
	new_task->taskid = 0; /* taskid will be allocated later */
	new_task->flags = flags;

	new_task->npool = npool;
	/* TODO: check error of get_user */
	for (i = 0; i < npool; ++i) {
		get_user(new_task->pools[i].start, &pools[i].start);
		get_user(new_task->pools[i].end, &pools[i].end);
		get_user(new_task->pools[i].mode, &pools[i].mode);
		/* Initialize new_task->pools[i].
		 * Actual marking is done later in orbit_call. */
		snap_init(&new_task->pools[i].snapshot);
		new_task->pools[i].data = NULL;
	}

	// FIXME: npool can be 0 when argsize is > 0
	if (argsize) {
		if (copy_from_user(new_task->pools + npool, arg, argsize)) {
			pr_err(PREFIX "failed to copy args for orbit task\n");
			return NULL;
		}
	}

	return new_task;
}

SYSCALL_DEFINE5(orbit_create, const char __user *, name, void __user *, argbuf,
		pid_t __user *, mpid, obid_t __user *, lobid,
		orbit_entry __user *, funcptr)
{
	struct task_struct *p, *parent;
	struct orbit_info *info;
	struct pid *pid;

	p = fork_to_orbit(name, argbuf, funcptr);
	if (IS_ERR(p))
		return PTR_ERR(p);
	info = p->orbit_info;
	if (info == NULL) {
		printk(KERN_ERR PREFIX "orbit_info is unexpectedly NULL\n");
		return -EINVAL;
	}
	info->state = ORBIT_NEW;

	// add the newly created orbit task_struct to the parent's orbit
	// children list.
	parent = current->group_leader;
	write_lock(&orbitlist_lock);
	list_add_tail(&p->orbit_sibling, &parent->orbit_children);
	write_unlock(&orbitlist_lock);

	/* setup other fields of orbit_info */
	// the main PID of the orbit task is the parent task's PID
	info->mpid = task_pid_nr(parent);
	pid = get_task_pid(p, PIDTYPE_PID);
	info->gobid = pid_vnr(pid);
	// set the orbit id to the main program's last id + 1
	info->lobid = ++parent->last_obid;
	pr_info(PREFIX "created orbit task '%s' <LOID %d, GOID %d> for main "
		"program <PID %d>\n", info->name, info->lobid, info->gobid,
		info->mpid);
	// if user pointers are not null, save the orbit ids
	if (lobid != NULL)
		put_user(info->lobid, lobid);
	if (mpid != NULL)
		put_user(info->mpid, mpid);

	// waking up the orbit task before we return
	wake_up_new_task(p);
	put_pid(pid);
	info->state = ORBIT_STARTED;
	return info->gobid;
}

struct orbit_info *orbit_create_info(const char __user *name,
		void __user *argbuf, orbit_entry __user *funcptr)
{
	struct orbit_info *info;
	int error;

	info = kmalloc(sizeof(*info), GFP_KERNEL);
	if (info == NULL)
		return NULL;

	INIT_LIST_HEAD(&info->task_list);
	sema_init(&info->sem, 0);
	sema_init(&info->exit_sem, 0);
	spin_lock_init(&info->task_lock);
	info->current_task = info->next_task = NULL;
	info->argbuf = argbuf;
	info->funcptr = funcptr;
	info->taskid_counter = 0; /* valid taskid starts from 1 */
	if (name) {
		error = strncpy_from_user(info->name, name, ORBIT_NAME_LEN);
		if (error <= 0)
			strcpy(info->name, "anonymous");
	} else {
		strcpy(info->name, "anonymous");
	}

	return info;
}

bool signal_orbit_exit(struct task_struct *ob)
{
	struct orbit_info *info;
	struct list_head *iter;
	struct orbit_task *task;

	if (!(ob && ob->is_orbit && ob->orbit_info))
		return false;
	info = ob->orbit_info;

	/* TODO: should we just move this logic out of destroy? */
	// We should remove the orbit from the main's list only if the
	// orbit is not being explicitly destroyed.
	if (info->state  != ORBIT_STOPPED) {
		pr_info(PREFIX "orbit %d exits without being destroyed explicitly"
			", removing it from main's orbit_children\n", ob->pid);
		write_lock(&orbitlist_lock);
		if (ob->orbit_sibling.prev != LIST_POISON1)
			list_del(&ob->orbit_sibling);
		write_unlock(&orbitlist_lock);
	}
	// Need to up all the semaphores that the main program or the kernel
	// may be potentially waiting on for the orbit to prevent hanging
	info->state = ORBIT_DEAD;
	up(&info->sem);
	up(&info->exit_sem);
	spin_lock(&info->task_lock);
	list_for_each (iter, &info->task_list) {
		task = list_entry(iter, struct orbit_task, elem);
		// release all task update's lock and semaphore
		mutex_unlock(&task->updates_lock);
		up(&task->updates_sem);
		up(&task->finish);
	}
	spin_unlock(&info->task_lock);
	pr_info(PREFIX "orbit %d's locks and semaphores released\n", info->gobid);

	// TODO: clean up other resources as well here
	return true;
}

static int snapshot_share(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			  unsigned long addr);

/* Find the orbit in the current process' orbit list with the specified gobid.
 *
 * In the event that the main program has restarted while the orbit is not,
 * the orbit may not appear in the current process' list any more. We need
 * to search the global task list and fix this.
 *
 * Returns the orbit_info. If argument orbit is not null, the associated 
 * task_struct for the orbit is stored. */
struct orbit_info *find_orbit_by_gobid(obid_t gobid, struct task_struct **orbit)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;

	info = NULL;
	parent = current->group_leader;
	read_lock(&orbitlist_lock);
	list_for_each_entry (ob, &parent->orbit_children, orbit_sibling) {
		if (ob->orbit_info != NULL && ob->orbit_info->gobid == gobid) {
			info = ob->orbit_info;
			break;
		}
	}
	read_unlock(&orbitlist_lock);
	// TODO: when the gobid is not in the current's list, we should fall
	// back to the global task list.
	if (info && orbit)
		*orbit = ob;
	return info;
}

/* FIXME: Currently we send a task to the orbit, and let the orbit child to
 * create a snapshot actively. When should the snapshot timepoint happen?
 * Should it be right after the orbit call? If so, we may need to wait for the
 * orbit to finish its last task. */

/* Return value: In sync mode, this call returns the checker's return value.
 * In async mode, this returns a taskid integer. */
internalreturn orbit_call_internal(unsigned long flags, obid_t gobid,
				   size_t npool,
				   struct orbit_pool_range __user *pools,
				   orbit_entry func, void __user *arg,
				   size_t argsize)
{
	struct task_struct *ob, *parent;
	struct vm_area_struct *ob_vma, *parent_vma;
	struct orbit_info *info;
	struct orbit_task *new_task;
	unsigned long ret, taskid;
	size_t i;

	/* TODO: allow orbit to determine maximum acceptable arg buf size */
	if (argsize >= ARG_SIZE_MAX)
		return -EINVAL;

	/* 1. Find orbit_info by obid from the parent's orbit_children list. */
	info = find_orbit_by_gobid(gobid, &ob);
	if (info == NULL) {
		pr_err(PREFIX "cannot find orbit %d\n", gobid);
		return -EINVAL;
	}
	orb_dbg("adding to orbit %d's task queue\n", gobid);

	/* 2. Create a orbit task struct and add to the orbit's task queue. */
	new_task = orbit_create_task(flags, func, arg, argsize, npool, pools);
	if (new_task == NULL)
		return -ENOMEM;

	orb_dbg("arg = %p, new_task->arg = %p\n", arg, new_task->arg);

	parent = current->group_leader;
	/* Serialized marking protected parent mmap_sem.
	 * We do not allow parallel snapshotting in current design. */
	/* if (down_write_killable(&parent->mm->mmap_sem)) { */
	if (down_read_killable(&parent->mm->mmap_sem)) {
		ret = -EINTR;
		pr_err(PREFIX "orbit call cannot acquire parent sem");
		goto bad_orbit_call_cleanup;
	}

	for (i = 0; i < npool; ++i) {
		struct orbit_pool_snapshot *pool = new_task->pools + i;

		parent_vma = find_vma(parent->mm, pool->start);

		orb_dbg("pool %ld size %ld", i, pool->end - pool->start);
		/* TODO: kernel rules for cow */
		/* if (pool->end - pool->start <= 8192) { */
		if (pool->mode == ORBIT_COPY) {
			size_t pool_size = pool->end - pool->start;
			if (pool_size == 0) {
				pool->data = NULL;
				continue;
			}
			pool->data = kmalloc(pool_size, GFP_KERNEL);
			if (pool->data) {
				orb_dbg("Orbit allocated %ld\n", pool_size);
			} else {
				ret = -ENOMEM;
				pr_err(PREFIX "OOM in orbit pool alloc %ld\n",
				       pool_size);
				// up semaphore before cleanup
				up_read(&parent->mm->mmap_sem);
				goto bad_orbit_call_cleanup;
			}
			up_read(&parent->mm->mmap_sem);
			if (copy_from_user(pool->data,
					   (const void __user *)pool->start,
					   pool_size)) {
				ret = -EINVAL;
				pr_err(PREFIX
				       "failed to copy pool data from user\n");
				goto bad_orbit_call_cleanup;
			}
			orb_dbg("copied\n");
			if (down_read_killable(&parent->mm->mmap_sem))
				panic("down failed");
		} else if (list_empty(&info->task_list)) {
			/* We probably don't need ob's mmap_sem since
			 * there is no task running. */
			ob_vma = find_vma(ob->mm, pool->start);
			ret = update_page_range(ob->mm, parent->mm, ob_vma,
						parent_vma, pool->start,
						pool->end,
						ORBIT_UPDATE_SNAPSHOT, NULL);
		} else {
			/* TODO: ORBIT_MOVE */
			ret = update_page_range(NULL, parent->mm, NULL,
						parent_vma, pool->start,
						pool->end, ORBIT_UPDATE_MARK,
						&pool->snapshot);
		}
	}

	/* up_write(&parent->mm->mmap_sem); */
	up_read(&parent->mm->mmap_sem);

	/* Add task to the queue */
	/* TODO: make killable? */
	spin_lock(&info->task_lock);

	/* Allocate taskid; valid taskid starts from 1 */
	/* TODO: will this overflow? */
	taskid = new_task->taskid = ++info->taskid_counter;
	list_add_tail(&new_task->elem, &info->task_list);
	if (info->next_task == NULL)
		info->next_task = new_task;
	spin_unlock(&info->task_lock);
	up(&info->sem);

	/* 3. Return from main in async mode, */
	if (flags & ORBIT_ASYNC)
		return taskid;
	/* or wait for the task to finish */
	down(&new_task->finish); /* TODO: make killable? */
	ret = new_task->retval;

	/* free_task: */
	kfree(new_task);
	return ret;

bad_orbit_call_cleanup:
	for (i = 0; i < npool; ++i) {
		struct orbit_pool_snapshot *pool = new_task->pools + i;
		if (pool->mode != ORBIT_COPY && pool->data)
			kfree(pool->data);
	}
	kfree(new_task);
	return ret;
}

SYSCALL_DEFINE1(orbit_call, struct orbit_call_args __user *, uargs)
{
	struct orbit_call_args args;

	if (copy_from_user(&args, uargs, sizeof(struct orbit_call_args)))
		return -EINVAL;

	return orbit_call_internal(args.flags, args.gobid,
		args.npool, args.pools, args.func, args.arg, args.argsize);
}

SYSCALL_DEFINE1(orbit_destroy, obid_t, gobid)
{
	struct orbit_info *info;
	struct task_struct *ob;
	struct pid *pid, *tgid;
	int ret;

	info = find_orbit_by_gobid(gobid, &ob);
	if (info == NULL)
		return -EINVAL;
	info->state = ORBIT_STOPPED;
	pid = task_pid(ob);
	tgid = task_tgid(ob);
	pr_info(PREFIX "to kill orbit pid (%d, %p) tgid (%d, %p)\n", ob->pid,
		pid, ob->tgid, tgid);
	write_lock(&orbitlist_lock);
	list_del(&ob->orbit_sibling);
	pr_info(PREFIX "removed orbit %d from main's orbit_children\n", ob->pid);
	write_unlock(&orbitlist_lock);
	pr_info(PREFIX "orbit %d's state is %ld\n", ob->pid, ob->state);
	// inc ref count of the struct so we can access it after it's killed
	get_task_struct(ob);
	ret = do_send_sig_info(SIGKILL, SEND_SIG_PRIV, ob, PIDTYPE_TGID);
	pr_info(PREFIX "%s orbit %d of the main program %d\n",
		(ret == 0) ? "terminated" : "failed to terminate",
		info->lobid, info->mpid);
	/*
	 * There can be a time delay between sending the SIGKILL to the orbit
	 * task getting the signal, notifying its parent, and reaping itself.
	 * Thus, checking the orbit after orbit_destroy returns can still
	 * succeed.
	 *
	 * Here we add an `exit_sem` field in orbit_info to try to ensure the
	 * orbit finishes reaping itself before the 'orbit_destroy' returns.
	 * The exit_notify function in kernel/exit.c will signal this semaphore.
	 *
	 * To avoid potential indefinite blocking, use down_timeout instead of
	 * down. The msecs_to_jiffies are a bit inaccurate. Using a small value
	 * like 5 ms can cause premature returns even though the time has not
	 * elapsed for more than 5 ms. Use a conservative 1000 ms timeout.
	 *
	 */
	if (down_timeout(&ob->orbit_info->exit_sem, msecs_to_jiffies(1000)))
		pr_info(PREFIX "timeout in waiting for orbit exit signal, "
			"orbit exit state is %d\n", ob->exit_state);
	// dec ref count of the task struct
	put_task_struct(ob);
	return 0;
}

SYSCALL_DEFINE0(orbit_destroy_all)
{
	struct list_head *pos, *q;
	struct task_struct *ob, *parent;
	struct orbit_info *info;

	info = NULL;
	parent = current->group_leader;
	write_lock(&orbitlist_lock);
	list_for_each_safe(pos, q, &parent->orbit_children) {
		ob = list_entry(pos, struct task_struct, orbit_sibling);
		get_task_struct(ob);
		list_del(pos);
		pr_info(PREFIX "removed orbit %d from main's orbit_children\n", ob->pid);
		if (ob->orbit_info != NULL) {
			info = ob->orbit_info;
			info->state = ORBIT_STOPPED;
			do_send_sig_info(SIGKILL, SEND_SIG_PRIV, ob,
					 PIDTYPE_TGID);
			pr_info(PREFIX
				"terminated orbit %d of the main program %d\n",
				info->lobid, info->mpid);
			if (down_timeout(&ob->orbit_info->exit_sem,
					 msecs_to_jiffies(1000)))
				pr_info(PREFIX
					"timeout in waiting for orbit exit signal, "
					"orbit exit state is %d\n",
					ob->exit_state);
		}
		put_task_struct(ob);
	}
	write_unlock(&orbitlist_lock);
	return 0;
}

SYSCALL_DEFINE2(orbit_state, obid_t, gobid, enum orbit_state *, state)
{
	struct orbit_info *info;
	struct task_struct *ob;

	info = find_orbit_by_gobid(gobid, &ob);
	if (info == NULL)
		return -EINVAL;
	if (state)
		put_user(info->state, state);
	return 0;
}

#define ORBIT_BUFFER_MAX                                                       \
	4096 /* Maximum buffer size of orbit_update data field */

struct orbit_update_user {
	void __user *ptr;
	size_t length;
	char data[];
};

struct orbit_update {
	struct list_head elem;
	struct orbit_update_user userdata;
};

static struct orbit_update *orbit_create_update(size_t length)
{
	struct orbit_update *new_update;

	new_update = kmalloc(sizeof(struct orbit_update) + length, GFP_KERNEL);
	if (new_update == NULL)
		return NULL;
	INIT_LIST_HEAD(&new_update->elem);

	return new_update;
}

/* Return value: 0 for success, other value for failure */
internalreturn
orbit_send_internal(const struct orbit_update_user __user *update)
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

#ifdef DEBUG_COPY_MEMCPY
	memcpy(&new_update->userdata, update,
	       sizeof(struct orbit_update_user) + length);
#else
	if (copy_from_user(&new_update->userdata, update,
			   sizeof(struct orbit_update_user) + length))
		return -EINVAL;
#endif

	mutex_lock(&current_task->updates_lock);
	refcount_inc(&current_task->refcount);
	list_add_tail(&new_update->elem, &current_task->updates);
	mutex_unlock(&current_task->updates_lock);
	up(&current_task->updates_sem);

	return 0;
}

SYSCALL_DEFINE1(orbit_send, const struct orbit_update_user __user *, update)
{
	return orbit_send_internal(update);
}

/* Return value: 0 for success, other value for failure */
internalreturn orbit_recv_internal(obid_t gobid, unsigned long taskid,
				   struct orbit_update_user __user *update_user)
{
	struct orbit_info *info;
	struct orbit_task *task;
	struct orbit_update *update;
	struct list_head *iter;
	int found = 0;

	info = find_orbit_by_gobid(gobid, NULL);
	if (info == NULL) {
		printk(KERN_WARNING PREFIX "cannot find orbit %d\n", gobid);
		return -EINVAL;
	}

	/* TODO: maybe use rbtree along with the list? */
	spin_lock(&info->task_lock);
	list_for_each (iter, &info->task_list) {
		task = list_entry(iter, struct orbit_task, elem);
		if (task->taskid == taskid) {
			found = 1;
			break;
		}
	}
	spin_unlock(&info->task_lock);

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
		return -EIDRM; /* End of message list. */
	}
	update = list_first_entry(&task->updates, struct orbit_update, elem);
	list_del(&update->elem);
	mutex_unlock(&task->updates_lock);

#ifdef DEBUG_COPY_MEMCPY
	memcpy(update_user, &update->userdata,
	       sizeof(struct orbit_update_user) + update->userdata.length);
#else
	if (copy_to_user(update_user, &update->userdata,
			 sizeof(struct orbit_update_user) +
				 update->userdata.length))
		return -EINVAL;
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

SYSCALL_DEFINE3(orbit_recv, obid_t, gobid, unsigned long, taskid,
		struct orbit_update_user __user *, update_user)
{
	return orbit_recv_internal(gobid, taskid, update_user);
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
internalreturn orbit_return_internal(unsigned long retval)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *task; /* Both old and new task. */
	struct vm_area_struct *ob_vma;
	struct orbit_pool_snapshot *pool;

	if (!current->is_orbit) {
		printk("calling orbit_return on a non-orbit task\n");
		return -EINVAL;
	}
	if (!current->orbit_main) {
		printk("the main process of the orbit is unknown\n");
		return -EINVAL;
	}

	ob = current;
	parent = ob->orbit_main;
	info = ob->orbit_info;

	/* First half: return value to parent */
	task = info->current_task;
	/* Current task can be NULL: in the current implementation, the orbit
	 * does not run any checker code before the first entrance to
	 * orbit_return. */
	if (task != NULL) {
		task->retval = retval;

		orb_dbg("orbit return locking\n");
		spin_lock(&info->task_lock);
		orb_dbg("orbit return locked\n");

		info->next_task = list_is_last(&task->elem, &info->task_list) ?
					  NULL :
					  list_next_entry(task, elem);

		if (task->flags & ORBIT_ASYNC) {
			/* If the user does not want output,
			 * dec refcount and try to cleanup.
			 * Orbit_recv function will also try to cleanup.
			 */
			if (task->flags & ORBIT_NORETVAL) {
				up(&task->finish);
				if (refcount_read(&task->refcount) == 0 &&
				    down_trylock(&task->finish) == 0) {
					list_del(&task->elem);
					kfree(task);
				}
			} else {
				up(&task->finish);
				up(&task->updates_sem);
			}
		} else {
			/* Otherwise, orbit_call will wait for down(). */
			list_del(&task->elem);
			up(&task->finish);
		}

		spin_unlock(&info->task_lock);
		orb_dbg("orbit return unlocked\n");
	}

	/* Second half: handle the next task */

	/* 1. Wait for a task to come in */
	/* TODO: make killable? */
	orb_dbg("orbit return down\n");
	if (down_killable(&info->sem)) {
		pr_info(PREFIX "orbit %d interrupted while waiting for tasks",
			ob->pid);
		return -EINTR;
	}
	orb_dbg("orbit return downed\n");
	spin_lock(&info->task_lock);
	orb_dbg("orbit return locked 2\n");
	info->current_task = task = info->next_task;
	info->next_task = list_is_last(&task->elem, &info->task_list) ?
				  NULL :
				  list_next_entry(task, elem);
	spin_unlock(&info->task_lock);
	orb_dbg("orbit return unlocked 2\n");

	/* if (down_write_killable(&ob->mm->mmap_sem)) { */
	if (down_read_killable(&ob->mm->mmap_sem)) {
		retval = -EINTR;
		panic("orbit return cannot acquire orbit sem");
	}

	/* 2. Snapshot the page range */
	for (pool = task->pools; pool < task->pools + task->npool; ++pool) {
		/* FIXME: this should be in a generic logic */
		if (pool->start == pool->end)
			continue;
		/* TODO: vma return value error handling */
		ob_vma = find_vma(ob->mm, pool->start);
		/* vma_interval_tree_iter_first() */
		/* Currently we assume that the range will only be in one vma */
		whatis(ob_vma->vm_start);
		whatis(ob_vma->vm_end);
		whatis(pool->start);
		whatis(pool->end);

		if (!(ob_vma->vm_start <= pool->start &&
		      pool->end <= ob_vma->vm_end)) {
			/* TODO: cleanup  */
			up_read(&ob->mm->mmap_sem);
			pr_err(PREFIX
			       "invalid address range of pool %ld: <vma_start %lx, "
			       "vma_end %lx> <pool_start %lx, pool_end %lx>",
			       pool - task->pools, ob_vma->vm_start,
			       ob_vma->vm_end, pool->start, pool->end);
			return -EINVAL;
		}
		/* TODO: Update orbit vma list */
		/* Copy page range */

		/* FIXME: snapshot_share does not work with implicit vma_share */
		/* if (!(ob_vma->vm_start <= pool->start &&
			pool->end <= ob_vma->vm_start))
			snapshot_share(ob->mm, parent->mm, parent_vma); */

		orb_dbg("orbit apply pool %ld %d %ld\n", pool - task->pools,
		       !!pool->data, pool->snapshot.count);
		orb_dbg("snapshot pte count is %ld\n", pool->snapshot.count);
		if (pool->data) {
			orb_dbg("access_ok %ld\n",
			       access_ok(pool->start, pool->end - pool->start));
			/* up_write(&ob->mm->mmap_sem); */
			if (copy_to_user((void __user *)pool->start, pool->data,
					 pool->end - pool->start))
				pr_err(PREFIX "orbit failed to apply data\n");
			/* if (down_write_killable(&ob->mm->mmap_sem))
				panic("down failed"); */
			kfree(pool->data);
			orb_dbg("orbit apply freed\n");
			pool->data = NULL;
		} else if (pool->snapshot.count != 0)
			update_page_range(ob->mm, NULL, ob_vma, NULL,
					  pool->start, pool->end,
					  ORBIT_UPDATE_APPLY, &pool->snapshot);
		orb_dbg("snapshot pte count left %ld", pool->snapshot.count);
		snap_destroy(&pool->snapshot);
	}

	/* up_write(&ob->mm->mmap_sem); */
	up_read(&ob->mm->mmap_sem);
	orb_dbg("orbit apply up\n");

	/* 3. Setup the user argument to call entry_func.
	 * Current implementation is that the user runtime library passes
	 * a pointer to a buffer (void*) of size ARG_SIZE_MAX to orbit_create.
	 * Upon each orbit_call, the father passes a argument pointer to the
	 * syscall. The kernel will copy the arg to kernel space and copy to
	 * the argbuf upon orbit_return.
	 */
	orb_dbg("task->arg = %p, info->argbuf = %p\n", task->arg, info->argbuf);
	orb_dbg("task->func = %p, info->funcptr = %p\n", task->func, info->funcptr);
	if (task->argsize) {
		if (copy_to_user(info->argbuf, task->pools + task->npool,
				 task->argsize))
			return -EINVAL;
	}
	/* TODO: Clean up or kill? */
	if (copy_to_user(info->funcptr, &task->func, sizeof(orbit_entry)))
		return -EINVAL;

	/* 4. Return to userspace to start checker code */
	return task->taskid;
}

SYSCALL_DEFINE1(orbit_return, unsigned long, retval)
{
	return orbit_return_internal(retval);
}

/* Commit the changes made in the orbit.
 * This is a page-level granularity update.
 * This will automatically find the dirty pages and update back to main program. */
internalreturn do_orbit_commit(void)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *task; /* Both old and new task. */
	struct vm_area_struct *ob_vma, *parent_vma;
	int ret;
	struct orbit_pool_snapshot *pool;

	if (!current->is_orbit)
		return -EINVAL;

	ob = current;
	parent = ob->orbit_main;
	info = ob->orbit_info;

	task = info->current_task;

	for (pool = task->pools; pool < task->pools + task->npool; ++pool) {
		ob_vma = find_vma(ob->mm, pool->start);
		parent_vma = find_vma(parent->mm, pool->start);
		ret = update_page_range(parent->mm, ob->mm, parent_vma, ob_vma,
					pool->start, pool->end,
					ORBIT_UPDATE_DIRTY, NULL);
	}

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
	size_t count; /* Number of elements */
};

union orbit_result {
	unsigned long retval;
	struct orbit_scratch scratch;
};

struct orbit_update_v {
	struct list_head elem;
	struct orbit_scratch userdata;
};

static struct orbit_update_v *orbit_create_update_v(void)
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
	struct orbit_task *current_task; /* Both old and new task. */
	struct vm_area_struct *ob_vma, *parent_vma;
	int ret = 0;
	struct orbit_update_v *new_update;
	unsigned long scratch_start, scratch_end;

	if (!current->is_orbit)
		return -EINVAL;

	ob = current;
	parent = ob->orbit_main;
	info = ob->orbit_info;

	current_task = info->current_task;

	/* This syscall is only available for async mode tasks. */
	if (!(current_task->flags & ORBIT_ASYNC))
		return -EINVAL;

	new_update = orbit_create_update_v();
	if (new_update == NULL)
		return -ENOMEM;

#ifdef DEBUG_COPY_MEMCPY
	memcpy(&new_update->userdata, s, sizeof(struct orbit_scratch));
#else
	if (copy_from_user(&new_update->userdata, s,
			   sizeof(struct orbit_scratch)))
		return -EINVAL;
#endif

	scratch_start = (unsigned long)new_update->userdata.ptr;
	scratch_end = scratch_start + new_update->userdata.size_limit;

	/* FIXME: synchronization */
	ob_vma = find_vma(ob->mm, scratch_start);
	parent_vma = find_vma(parent->mm, scratch_start);
	ret = update_page_range(parent->mm, ob->mm, parent_vma, ob_vma,
				scratch_start, scratch_end,
				ORBIT_UPDATE_SNAPSHOT, NULL);
	if (ret) {
		kfree(new_update);
		return ret;
	}

	mutex_lock(&current_task->updates_lock);
	refcount_inc(&current_task->refcount);
	list_add_tail(&new_update->elem, &current_task->updates);
	mutex_unlock(&current_task->updates_lock);
	up(&current_task->updates_sem);

	return 0;
}

SYSCALL_DEFINE1(orbit_sendv, struct orbit_scratch __user *, s)
{
	return do_orbit_sendv(s);
}

/* Returns 1 on success. Returns 0 on end of updates. Returns -ERR on error. */
internalreturn do_orbit_recvv(union orbit_result __user *result, obid_t gobid,
			      unsigned long taskid)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *task; /* Both old and new task. */
	struct orbit_update_v *update;
	int ret;
	struct list_head *iter;
	int found = 0;
	int list_count = 0;

	info = find_orbit_by_gobid(gobid, &ob);
	if (info == NULL) {
		printk(KERN_WARNING PREFIX "cannot find orbit %d\n", gobid);
		return -EINVAL;
	}
	parent = current->group_leader;
	task = info->current_task;

	/* TODO: maybe use rbtree along with the list? */
	spin_lock(&info->task_lock);
	list_for_each (iter, &info->task_list) {
		++list_count;
		task = list_entry(iter, struct orbit_task, elem);
		if (task->taskid == taskid) {
			found = 1;
			break;
		}
	}
	spin_unlock(&info->task_lock);

	if (list_count > 100)
		printk("warning: orbit list size %d", list_count);

	if (!found) {
		printk("taskid %lu not found", taskid);
		return -EINVAL;
	}

	/* This syscall is only available for async mode tasks. */
	if (!(task->flags & ORBIT_ASYNC))
		return -EINVAL;

	/* Now get one of the updates */
	/* FIXME: Fix this messy wakeup & cleanup logic */
	down(&task->updates_sem);
	mutex_lock(&task->updates_lock);

	/* It is a return. */
	if (list_empty(&task->updates)) {
		if (task->retval == -ESRCH) {
			ret = -ESRCH;
		} else {
			put_user(task->retval, &result->retval);
			/* TODO: cleanup the task */
			ret = 0; /* End of updates. */
		}
	} else {
		update = list_first_entry(&task->updates, struct orbit_update_v,
					  elem);
		list_del(&update->elem);

#ifdef DEBUG_COPY_MEMCPY
		memcpy(&result->scratch, &update->userdata,
		       sizeof(struct orbit_scratch));
#else
		if (copy_to_user(&result->scratch, &update->userdata,
				 sizeof(struct orbit_scratch)))
			return -EINVAL;
#endif
		kfree(update);

		ret = 1;
	}
	mutex_unlock(&task->updates_lock);

	/* ARC free task object */
	/* if (ret == 0 && refcount_dec_and_test(&task->refcount) == 1 &&
		down_trylock(&task->finish) == 0) */
	if (ret != 1 && down_trylock(&task->finish) == 0) {
		spin_lock(&info->task_lock);
		list_del(&task->elem);
		spin_unlock(&info->task_lock);
		kfree(task);
	}

	return ret;
}

SYSCALL_DEFINE3(orbit_recvv, union orbit_result __user *, result, obid_t, gobid,
		unsigned long, taskid)
{
	return do_orbit_recvv(result, gobid, taskid);
}

internalreturn do_orbit_mmap(unsigned long addr, unsigned long len,
			     int is_scratch)
{
	unsigned long area;
	int ret;

	/* Currently we only support creating scratch in the child. */
	if (!(current->is_orbit && is_scratch))
		return -EINVAL;

	area = ksys_mmap_pgoff(addr, len, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if ((long)area <= 0)
		return area;

	/* FIXME: snapshot_share does not work with implicit vma_merge */
	ret = snapshot_share(current->orbit_main->mm, current->mm, area);
	/* How to handle ret? */
	orb_dbg("snapshot_share returns %d", ret);

	return area;
}

SYSCALL_DEFINE3(orbit_mmap, unsigned long, addr, unsigned long, len, int,
		is_scratch)
{
	return do_orbit_mmap(addr, len, is_scratch);
}

/* TODO: consider no mmu? */
/* #ifdef CONFIG_MMU */
/* This is copied and modified from dup_mmap(). */
static int snapshot_share(struct mm_struct *dst_mm, struct mm_struct *src_mm,
			  unsigned long addr)
{
	struct vm_area_struct *mpnt, *dst_near, *tmp;
	int retval = 0;
	unsigned long charge;
	LIST_HEAD(uf);

	if (down_write_killable(&src_mm->mmap_sem)) {
		retval = -EINTR;
		goto src_sema_fail;
	}
	/*
	 * TODO: this may incur deadlock!
	 */
	down_write_nested(&dst_mm->mmap_sem, SINGLE_DEPTH_NESTING);

	/* === Begin copy vma === */

	/* Find src vma.
	 * The area should have addr < vm_end, and addr == vm_start */
	mpnt = find_vma(src_mm, addr);
	if (mpnt == NULL)
		panic("mpnt is NULL!");
	if (mpnt->vm_start != addr)
		panic("mpnt->vm_start %lx, addr %lx", mpnt->vm_start, addr);

	/* Check that dst has the same free area.
	 * This can be potentially skipped if we allow snapshot at different
	 * addresses in main program and orbit. */
	dst_near = find_vma(dst_mm, addr);
	orb_dbg("mpnt->vm_end %lx dst_near->vm_start %lx", mpnt->vm_end,
	       dst_near->vm_start);
	if (!(mpnt->vm_end < dst_near->vm_start)) {
		panic("dst does not have space!");
		retval = -EINTR;
		goto out;
	}

	if (mpnt->vm_flags & VM_DONTCOPY)
		goto out;
	charge = 0;
	/*
	 * Don't duplicate many vmas if we've been oom-killed (for
	 * example)
	 */
	if (fatal_signal_pending(current)) {
		retval = -EINTR;
		goto out;
	}

	/* This is basically all userspace pages. */
	if (mpnt->vm_flags & VM_ACCOUNT) {
		unsigned long len = vma_pages(mpnt);

		if (security_vm_enough_memory_mm(src_mm, len)) /* sic */
			goto fail_nomem;
		charge = len;
	}
	tmp = vm_area_dup(mpnt);
	if (!tmp)
		goto fail_nomem;

	retval = vma_dup_policy(mpnt, tmp);
	if (retval)
		goto fail_nomem_policy;

	tmp->vm_mm = dst_mm;
	retval = dup_userfaultfd(tmp, &uf);
	if (retval)
		goto fail_nomem_anon_vma_fork;

	if (tmp->vm_flags & VM_WIPEONFORK) {
		/* VM_WIPEONFORK gets a clean slate in the child. */
		tmp->anon_vma = NULL;
		if (anon_vma_prepare(tmp))
			goto fail_nomem_anon_vma_fork;
	} else if (anon_vma_fork(tmp, mpnt))
		goto fail_nomem_anon_vma_fork;

	tmp->vm_flags &= ~(VM_LOCKED | VM_LOCKONFAULT);
	tmp->vm_next = tmp->vm_prev = NULL;

	/* This should always be NULL for our use */
	if (tmp->vm_file != NULL)
		panic("tmp->vm_file not NULL");
	tmp->vm_file = NULL;
	/*
	 * Clear hugetlb-related page reserves for children. This only
	 * affects MAP_PRIVATE mappings. Faults generated by the child
	 * are not guaranteed to succeed, even if read-only
	 */
	/* TODO: support huge pages? */
	if (is_vm_hugetlb_page(tmp))
		reset_vma_resv_huge_pages(tmp);

	/*
	 * Link in the new vma and copy the page table entries.
	 */
	insert_vm_struct(dst_mm, tmp);

	/* TODO: new anon map should have all empty pages,
	 * so we could probably skip this step? */
	if (!(tmp->vm_flags & VM_WIPEONFORK))
		retval = copy_page_range(dst_mm, src_mm, mpnt);

	if (tmp->vm_ops && tmp->vm_ops->open)
		tmp->vm_ops->open(tmp);

	/* === End copy vma === */

	vm_stat_account(dst_mm, mpnt->vm_flags, vma_pages(mpnt));
	vm_acct_memory(charge);

out:
	up_write(&dst_mm->mmap_sem);
	flush_tlb_mm(src_mm);
	up_write(&src_mm->mmap_sem);
	dup_userfaultfd_complete(&uf);

src_sema_fail:
	return retval;

fail_nomem_anon_vma_fork:
	mpol_put(vma_policy(tmp));
fail_nomem_policy:
	vm_area_free(tmp);
fail_nomem:
	retval = -ENOMEM;
	goto out;
}
