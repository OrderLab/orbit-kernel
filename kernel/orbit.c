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

#define ARG_SIZE_MAX 1024

__cacheline_aligned DEFINE_RWLOCK(orbitlist_lock);

void snap_init(struct vma_snapshot *snap);
void snap_destroy(struct vma_snapshot *snap);

static int orbit_cancel(struct orbit_cancel_args *args);
static bool orbit_skippable(struct orbit_info *info,
		struct orbit_task *new_task, int flags);

static struct orbit_task *
orbit_create_task(unsigned long flags, orbit_entry func, void __user *arg,
		  size_t argsize, size_t narea,
		  struct orbit_area_range __user *areas)
{
	struct orbit_task *new_task;
	size_t i;

	new_task = kmalloc(sizeof(*new_task) + argsize +
				   narea * sizeof(struct orbit_area_snapshot),
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
	new_task->argsize = argsize;
	new_task->taskid = 0; /* taskid will be allocated later */
	new_task->flags = flags;
	new_task->cancelled = false;

	new_task->narea = narea;
	/* TODO: check error of get_user */
	for (i = 0; i < narea; ++i) {
		get_user(new_task->areas[i].start, &areas[i].start);
		get_user(new_task->areas[i].end, &areas[i].end);
		get_user(new_task->areas[i].mode, &areas[i].mode);
		/* Initialize new_task->areas[i].
		 * Actual marking is done later in orbit_call. */
		snap_init(&new_task->areas[i].snapshot);
		new_task->areas[i].data = NULL;
	}

	// FIXME: narea can be 0 when argsize is > 0
	if (argsize) {
		if (copy_from_user(task_argbuf(new_task), arg, argsize)) {
			pr_err(PREFIX "failed to copy args for orbit task\n");
			return NULL;
		}
	}

	return new_task;
}

/* Destroy a task
 * The task should have already been removed from the list. */
static void orbit_task_destroy(struct orbit_task *task)
{
	struct orbit_area_snapshot *area;

	orb_dbg("task_destroy id=%ld\n", task->taskid);

	for (area = task->areas; area < task->areas + task->narea; ++area) {
		if (area->start == area->end)
			continue;
		if (area->data)
			kfree(area->data);
		if (area->snapshot.count != 0)
			snap_destroy(&area->snapshot);
	}

	kfree(task);
}

static inline struct orbit_task *
get_next_task(struct list_head *list, struct orbit_task *task)
{
	if (task == NULL) return NULL;
	do {
		/* What..??? 1st arg `list` is the element?
		 * What a horrible naming of Linux kernel list. */
		if (list_is_last(&task->elem, list))
			return NULL;
		task = list_next_entry(task, elem);
	} while (task->cancelled);
	return task;
}

/* Helper task list for loop for not cancelled tasks.
 * A `tmp` is used incase list entry removal */
#define task_list_for_non_cancel_from_safe(task, tmp, task_list) \
	for (tmp = get_next_task(task_list, task); \
	     task; task = tmp, tmp = get_next_task(task_list, task))

/* ARC increment
 * This must be called holding info->task_lock */
static inline void task_get(struct orbit_task *task)
{
	refcount_inc(&task->refcount);
}

/* ARC decrement and release */
static inline void task_put(struct orbit_task *task, spinlock_t *info_lock)
{
	if (refcount_dec_and_lock(&task->refcount, info_lock)) {
		list_del(&task->elem);
		spin_unlock(info_lock);
		orbit_task_destroy(task);
	}
}

/* ARC decrement and release
 * This must be called holding info->task_lock */
static inline void task_put_locked(struct orbit_task *task)
{
	if (refcount_dec_and_test(&task->refcount)) {
		list_del(&task->elem);
		orbit_task_destroy(task);
	}
}

static void timing_reference(void)
{
	cycles_t clk1, clk2, clk3;
	u64 t1, t2, t3;
	int i;
	DEFINE_SPINLOCK(lock);

	printk("size of task = %lu\n", sizeof(struct task_struct));

	printk("unsynchronized_tsc = %d\n", unsynchronized_tsc());

	clk1 = get_cycles();
	clk2 = get_cycles();
	clk3 = get_cycles();

	printk("clk takes %lld %lld cycles", clk2 - clk1, clk3 - clk1);

	t1 = ktime_get_ns();
	t2 = ktime_get_ns();
	t3 = ktime_get_ns();

	printk("ktime takes %lld %lld ns", t2 - t1, t3 - t1);

	clk2 = clk3 = 0;

	for (i = 0; i < 10; ++i) {
		clk1 = get_cycles();
		spin_lock(&lock);
		clk2 += get_cycles() - clk1;

		clk1 = get_cycles();
		spin_unlock(&lock);
		clk3 += get_cycles() - clk1;
	}

	printk("avg cycles for spin lock: %lld\n", clk2 / 10);
	printk("avg cycles for spin unlock: %lld\n", clk3 / 10);
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
	info->snap_active = false;
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
	struct orbit_task *task, *next_task;

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
	task = info->current_task ? info->current_task : info->next_task;
	task_list_for_non_cancel_from_safe (task, next_task, &info->task_list) {
		task->cancelled = true;
		// release all task update's lock and semaphore
		mutex_unlock(&task->updates_lock);
		up(&task->updates_sem);
		up(&task->finish);
		task_put_locked(task);
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
				   size_t narea,
				   struct orbit_area_range __user *areas,
				   orbit_entry func, void __user *arg,
				   size_t argsize)
{
	struct task_struct *ob, *parent;
	struct vm_area_struct *parent_vma;
	struct orbit_info *info;
	struct orbit_task *new_task;
	struct orbit_cancel_args cancel_args;
	unsigned long ret, taskid;
	size_t i;
	bool active_held = false;

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
	new_task = orbit_create_task(flags, func, arg, argsize, narea, areas);
	if (new_task == NULL)
		return -ENOMEM;
	if (flags & (ORBIT_SKIP_SAME_ARG | ORBIT_SKIP_ANY)) {
		bool skippable;

		/* FIXME: Now only supports async. We may wait for finish
		 * for sync tasks. In that case, we will need to `up` when
		 * one receiver finished. */
		if (unlikely(!(flags & ORBIT_ASYNC)))
			panic("orbit: skip sync task not implemented yet!\n");

		spin_lock(&info->task_lock);
		skippable = orbit_skippable(info, new_task,
				flags & (ORBIT_SKIP_SAME_ARG | ORBIT_SKIP_ANY));
		spin_unlock(&info->task_lock);
		if (skippable) {
			/* Async orbit call 0 means skipped. */
			/* FIXME: how to receive results? */
			ret = 0;
			goto new_task;
		}
	}

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

	for (i = 0; i < narea; ++i) {
		struct orbit_area_snapshot *area = new_task->areas + i;

		parent_vma = find_vma(parent->mm, area->start);

		orb_dbg("area %ld size %ld", i, area->end - area->start);
		/* TODO: kernel rules for cow */
		/* if (area->end - area->start <= 8192) { */
		if (area->mode == ORBIT_COPY) {
			size_t area_size = area->end - area->start;
			if (area_size == 0) {
				area->data = NULL;
				continue;
			}
			area->data = kmalloc(area_size, GFP_KERNEL);
			if (area->data) {
				orb_dbg("Orbit allocated %ld\n", area_size);
			} else {
				ret = -ENOMEM;
				pr_err(PREFIX "OOM in orbit area alloc %ld\n",
				       area_size);
				// up semaphore before cleanup
				up_read(&parent->mm->mmap_sem);
				goto bad_orbit_call_cleanup;
			}
			up_read(&parent->mm->mmap_sem);
			if (copy_from_user(area->data,
					   (const void __user *)area->start,
					   area_size)) {
				ret = -EINVAL;
				pr_err(PREFIX
				       "failed to copy area data from user\n");
				goto bad_orbit_call_cleanup;
			}
			orb_dbg("copied\n");
			if (down_read_killable(&parent->mm->mmap_sem))
				panic("down failed");
		} else {
			/* TODO: ORBIT_MOVE */
			enum update_mode mode;
			struct mm_struct *ob_mm = NULL;
			struct vm_area_struct *ob_vma = NULL;
			struct vma_snapshot *snap = NULL;

			if (!active_held) {
				spin_lock(&info->task_lock);
				if (list_empty(&info->task_list) &&
					!info->snap_active) {
					info->snap_active = active_held = true;
				}
				spin_unlock(&info->task_lock);
			}

			if (active_held) {
				/* We probably don't need ob's mmap_sem since
				 * there is no task running. */
				mode = ORBIT_UPDATE_SNAPSHOT;
				ob_mm = ob->mm;
				ob_vma = find_vma(ob->mm, area->start);
			} else {
				mode = ORBIT_UPDATE_MARK;
				snap = &area->snapshot;
			}

			ret = update_page_range(ob_mm, parent->mm, ob_vma,
						parent_vma, area->start,
						area->end, mode, snap);
		}
	}

	/* up_write(&parent->mm->mmap_sem); */
	up_read(&parent->mm->mmap_sem);

	/* Add task to the queue */
	/* TODO: make killable? */
	spin_lock(&info->task_lock);
	if (active_held)
		info->snap_active = false;

	if (flags & ORBIT_CANCEL_SAME_ARG) {
		cancel_args = (struct orbit_cancel_args) {
			.info = info,
			.kind = ORBIT_CANCEL_ARGS,
			.arg = task_argbuf(new_task),
			.argsize = new_task->argsize,
		};
		orbit_cancel(&cancel_args);
	} else if (flags & ORBIT_CANCEL_ANY) {
		cancel_args = (struct orbit_cancel_args) {
			.info = info,
			.kind = ORBIT_CANCEL_KIND_ANY,
		};
		orbit_cancel(&cancel_args);
	}

	/* Allocate taskid; valid taskid starts from 1 */
	/* TODO: will this overflow? */
	taskid = new_task->taskid = ++info->taskid_counter;
	list_add_tail(&new_task->elem, &info->task_list);

	/* Count for orbit task to finish.
	 * Orbit side will not call task_get, but will task_put when finish. */
	task_get(new_task);
	/* For synchronous, we will be the waiter, so we hold the ARC.
	 * For asynchronous, we increment the refcount for updates as a whole,
	 * and recv will decrement the refcount when all updates has been
	 * retrieved. If we have ORBIT_NORETVAL, that means no update is
	 * needed, don't add refcount. In this case, finish will clean up
	 * the task.
	 * Note that this second task_get is intentional. */
	if (!(flags & ORBIT_ASYNC) || !(flags & ORBIT_NORETVAL))
		task_get(new_task);

	if (info->next_task == NULL)
		info->next_task = new_task;
	orb_dbg("task_next new id=%ld\n", info->next_task ? info->next_task->taskid : -1);

	spin_unlock(&info->task_lock);
	up(&info->sem);

	/* 3. Return from main in async mode, */
	if (flags & ORBIT_ASYNC)
		return taskid;
	/* or wait for the task to finish */
	down(&new_task->finish); /* TODO: make killable? */
	ret = new_task->retval;

	task_put(new_task, &info->task_lock);
	return ret;

bad_orbit_call_cleanup:
	for (i = 0; i < narea; ++i) {
		struct orbit_area_snapshot *area = new_task->areas + i;
		if (area->mode != ORBIT_COPY && area->data)
			kfree(area->data);
	}
new_task:
	kfree(new_task);
	return ret;
}

SYSCALL_DEFINE1(orbit_call, struct orbit_call_args __user *, uargs)
{
	struct orbit_call_args args;

	if (copy_from_user(&args, uargs, sizeof(struct orbit_call_args)))
		return -EINVAL;

	return orbit_call_internal(args.flags, args.gobid,
		args.narea, args.areas, args.func, args.arg, args.argsize);
}

/* Check whether the new task can be skipped.
 * This function must be called with info->lock held. */
static bool orbit_skippable(struct orbit_info *info,
		struct orbit_task *new_task, int flags)
{
	struct orbit_task *task, *tmp_task;

	/* TODO: Should we loop from the current task, or include finished
	 * tasks?  Current implementation: from the current task. */
	task = info->current_task ? info->current_task : info->next_task;
	task_list_for_non_cancel_from_safe (task, tmp_task, &info->task_list) {
		if ((flags & ORBIT_SKIP_ANY) ||
		    ((flags & ORBIT_SKIP_SAME_ARG) &&
		     task->argsize == new_task->argsize &&
		     !memcmp(task_argbuf(task), task_argbuf(new_task), task->argsize)))
		{
			return true;
		} else {
			/* For future extension */
		}
	}

	return false;
}

/* Kernel internal function to cancel an orbit task.
 * This function must be called with info->lock held.
 * If cancel was successful, return 1, otherwise return 0. */
static int orbit_cancel(struct orbit_cancel_args *args)
{
	struct orbit_info *info = args->info;
	struct orbit_task *task, *tmp_task;
	bool found = false;
	int downed;

	/* Loop from the next task. We will not the cancel running task.
	 * This is required, otherwise the loop will do cancel on finished
	 * tasks, and that will cause issues like refcount underflow. */
	task = info->next_task;
	task_list_for_non_cancel_from_safe (task, tmp_task, &info->task_list) {
		if ((task->flags & ORBIT_CANCELLABLE) &&
		    ((args->kind == ORBIT_CANCEL_TASKID &&
		      task->taskid == args->taskid) ||
		     (args->kind == ORBIT_CANCEL_ARGS &&
		      args->argsize == task->argsize &&
		      !memcmp(task_argbuf(task), args->arg, args->argsize)) ||
		     args->kind == ORBIT_CANCEL_KIND_ANY))
		{
			found = true;
			break;
		} else {
			/* For future extension */
		}
	}

	/* TODO: Should we return EINVAL if it has exited.
	 * We probably should distinct not found from other invalid args. */
	if (!found)
		return 0;
	orb_dbg("orbit: cancelling task %ld\n", task->taskid);

	task->cancelled = true;
	if (info->next_task == task)
		info->next_task = get_next_task(&info->task_list, task);
	orb_dbg("task_next cancel id=%ld\n", info->next_task ? info->next_task->taskid : -1);

	up(&task->finish);
	up(&task->updates_sem);
	/* We cannot definitively decrement the semaphore for the number of
	 * available tasks in the queue. Otherwise if orbit_return down first,
	 * we will hang indefinitely here. Therefore we do a best effort to
	 * down 1, otherwise down 0. Orbit side will see spurious wakeups, so
	 * also do a check there. */
	downed = down_trylock(&info->sem);

	/* Decrement on behalf of orbit_return */
	task_put_locked(task);

	return 1;
}

#define STACK_ARG_LIMIT 256

SYSCALL_DEFINE1(orbit_cancel, struct orbit_cancel_user_args __user *, _uargs)
{
	struct orbit_cancel_args args;
	struct orbit_cancel_user_args uargs;
	char buf_stack[STACK_ARG_LIMIT];
	char *buf = NULL;
	struct orbit_info *info = NULL;
	int ret;

	if (copy_from_user(&uargs, _uargs, sizeof(struct orbit_cancel_user_args)))
		return -EINVAL;

	args.info = info = find_orbit_by_gobid(uargs.gobid, NULL);
	if (info == NULL)
		return -EINVAL;
	args.kind = uargs.kind;

	if (uargs.kind == ORBIT_CANCEL_ARGS) {
		buf = uargs.argsize > STACK_ARG_LIMIT
			? kmalloc(uargs.argsize, GFP_KERNEL)
			: buf_stack;
		if (!buf) return -ENOMEM;
		if (copy_from_user(buf, uargs.arg, uargs.argsize)) {
			goto inval;
		}
		args.arg = buf;
		args.argsize = uargs.argsize;
	} else if (uargs.kind == ORBIT_CANCEL_TASKID) {
		args.taskid = uargs.taskid;
	} else {
		return -EINVAL;
	}

	spin_lock(&info->task_lock);
	ret = orbit_cancel(&args);
	spin_unlock(&info->task_lock);
	goto exit;
inval:
	ret = -EINVAL;
exit:
	if (buf != NULL && buf != buf_stack)
		kfree(buf);
	return ret;
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

#if 0
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
	int ret = 0;

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
			task_get(task);
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
		goto inval;

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

	goto exit;
inval:
	ret = -EINVAL;
exit:
	task_put(task, &info->task_lock);
	return ret;
}

SYSCALL_DEFINE3(orbit_recv, obid_t, gobid, unsigned long, taskid,
		struct orbit_update_user __user *, update_user)
{
	return orbit_recv_internal(gobid, taskid, update_user);
}
#endif

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
	struct orbit_area_snapshot *area;

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

		info->current_task = NULL;

		up(&task->finish);
		up(&task->updates_sem);
		orb_dbg("task_sem_up id=%ld sem = %d\n", task->taskid, task->updates_sem.count);

		task_put_locked(task);

		spin_unlock(&info->task_lock);
		orb_dbg("orbit return unlocked\n");
	}

	/* Second half: handle the next task */

	/* 1. Wait for a task to come in */
	do {
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
		info->next_task = get_next_task(&info->task_list, task);
		orb_dbg("task_current run id=%ld\n", task ? task->taskid : -1);
		orb_dbg("task_next run id=%ld\n", info->next_task ? info->next_task->taskid : -1);

		spin_unlock(&info->task_lock);
		orb_dbg("orbit return unlocked 2\n");
	} while (task == NULL);

	/* if (down_write_killable(&ob->mm->mmap_sem)) { */
	if (down_read_killable(&ob->mm->mmap_sem)) {
		retval = -EINTR;
		panic("orbit return cannot acquire orbit sem");
	}

	/* 2. Snapshot the page range */
	for (area = task->areas; area < task->areas + task->narea; ++area) {
		/* FIXME: this should be in a generic logic */
		if (area->start == area->end)
			continue;
		/* TODO: vma return value error handling */
		ob_vma = find_vma(ob->mm, area->start);
		/* vma_interval_tree_iter_first() */
		/* Currently we assume that the range will only be in one vma */
		whatis(ob_vma->vm_start);
		whatis(ob_vma->vm_end);
		whatis(area->start);
		whatis(area->end);

		if (!(ob_vma->vm_start <= area->start &&
		      area->end <= ob_vma->vm_end)) {
			/* TODO: cleanup  */
			up_read(&ob->mm->mmap_sem);
			pr_err(PREFIX
			       "invalid address range of area %ld: <vma_start %lx, "
			       "vma_end %lx> <area_start %lx, area_end %lx>",
			       area - task->areas, ob_vma->vm_start,
			       ob_vma->vm_end, area->start, area->end);
			return -EINVAL;
		}
		/* TODO: Update orbit vma list */
		/* Copy page range */

		/* FIXME: snapshot_share does not work with implicit vma_share */
		/* if (!(ob_vma->vm_start <= area->start &&
			area->end <= ob_vma->vm_start))
			snapshot_share(ob->mm, parent->mm, parent_vma); */

		orb_dbg("orbit apply area %ld %d %ld\n", area - task->areas,
		       !!area->data, area->snapshot.count);
		orb_dbg("snapshot pte count is %ld\n", area->snapshot.count);
		if (area->data) {
			orb_dbg("access_ok %ld\n",
			       access_ok(area->start, area->end - area->start));
			/* up_write(&ob->mm->mmap_sem); */
			if (copy_to_user((void __user *)area->start, area->data,
					 area->end - area->start))
				pr_err(PREFIX "orbit failed to apply data\n");
			/* if (down_write_killable(&ob->mm->mmap_sem))
				panic("down failed"); */
			kfree(area->data);
			orb_dbg("orbit apply freed\n");
			area->data = NULL;
		} else if (area->snapshot.count != 0)
			update_page_range(ob->mm, NULL, ob_vma, NULL,
					  area->start, area->end,
					  ORBIT_UPDATE_APPLY, &area->snapshot);
		orb_dbg("snapshot pte count left %ld", area->snapshot.count);
		snap_destroy(&area->snapshot);
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
	orb_dbg("info->argbuf = %p\n", info->argbuf);
	orb_dbg("task->func = %p, info->funcptr = %p\n", task->func, info->funcptr);
	if (task->argsize) {
		if (copy_to_user(info->argbuf, task_argbuf(task), task->argsize))
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

#if 0

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
	struct orbit_area_snapshot *area;

	if (!current->is_orbit)
		return -EINVAL;

	ob = current;
	parent = ob->orbit_main;
	info = ob->orbit_info;

	task = info->current_task;

	for (area = task->areas; area < task->areas + task->narea; ++area) {
		ob_vma = find_vma(ob->mm, area->start);
		parent_vma = find_vma(parent->mm, area->start);
		ret = update_page_range(parent->mm, ob->mm, parent_vma, ob_vma,
					area->start, area->end,
					ORBIT_UPDATE_DIRTY, NULL);
	}

	return ret;
}

SYSCALL_DEFINE0(orbit_commit)
{
	return do_orbit_commit();
}
#endif

/* Encoded orbit updates and operations. */
#if 0
struct orbit_scratch {
	void *ptr;
	size_t cursor;
	size_t size_limit;
	size_t count; /* Number of elements */
};
#endif

struct orbit_result_kernel {
	unsigned long retval;
	void* data_start;
	size_t data_length;
	void *updates;	/* actually struct __orbit_block_list* */
};

#if 0
union orbit_result_user {
	unsigned long retval;
	struct orbit_scratch scratch;
};
#endif

struct orbit_update_v {
	struct list_head elem;
	/* struct orbit_scratch userdata; */
	struct orbit_result_kernel userdata;
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

internalreturn do_orbit_push(struct orbit_result_kernel __user *s)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *current_task; /* Both old and new task. */
	struct vm_area_struct *ob_vma, *parent_vma;
	int ret = 0;
	struct orbit_update_v *new_update;
	unsigned long update_start, update_end;

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
	memcpy(&new_update->userdata, s, sizeof(*s));
#else
	if (copy_from_user(&new_update->userdata, s, sizeof(*s)))
		return -EINVAL;
#endif

	update_start = (unsigned long)new_update->userdata.data_start;
	update_end = update_start + new_update->userdata.data_length;

	/* FIXME: synchronization */
	ob_vma = find_vma(ob->mm, update_start);
	parent_vma = find_vma(parent->mm, update_start);
	ret = update_page_range(parent->mm, ob->mm, parent_vma, ob_vma,
				update_start, update_end,
				ORBIT_UPDATE_SNAPSHOT, NULL);
	if (ret) {
		kfree(new_update);
		return ret;
	}

	mutex_lock(&current_task->updates_lock);
	list_add_tail(&new_update->elem, &current_task->updates);
	mutex_unlock(&current_task->updates_lock);
	up(&current_task->updates_sem);

	return 0;
}

SYSCALL_DEFINE1(orbit_push, struct orbit_result_kernel __user *, s)
{
	return do_orbit_push(s);
}

/* Returns 1 on success. Returns 0 on end of updates. Returns -ERR on error. */
internalreturn do_orbit_pull(struct orbit_result_kernel __user *result, obid_t gobid,
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
			task_get(task);
			break;
		}
	}
	spin_unlock(&info->task_lock);

	if (list_count > 100)
		printk("warning: orbit list size %d", list_count);

	if (!found) {
		orb_dbg("taskid %lu not found", taskid);
		return -EINVAL;
	}

	/* This syscall is only available for async mode tasks. */
	if (!(task->flags & ORBIT_ASYNC))
		goto inval;

	/* Now get one of the updates */
	orb_dbg("task_recv_wait id=%ld\n", task->taskid);
	down(&task->updates_sem);
	orb_dbg("task_recv_awake id=%ld\n", task->taskid);
	mutex_lock(&task->updates_lock);

	/* It is a return. */
	if (list_empty(&task->updates)) {
		if (task->retval == -ESRCH) {
			ret = -ESRCH;
		} else {
			put_user(task->retval, &result->retval);
			ret = 0; /* End of updates. */
		}
		/* TODO: Let's assume there is only one waiter */
		/* Try clean up the task since all updates has been
		 * retrieved. Actual cleanup happens before return.
		 * Note that this second task_put is intentional. */
		task_put(task, &info->task_lock);
	} else {
		update = list_first_entry(&task->updates, struct orbit_update_v,
					  elem);
		list_del(&update->elem);

#ifdef DEBUG_COPY_MEMCPY
		memcpy(result, &update->userdata, sizeof(*result));
#else
		if (copy_to_user(result, &update->userdata, sizeof(*result)))
			/* FIXME: error handling */
			return -EINVAL;
#endif
		kfree(update);

		ret = 1;
	}
	mutex_unlock(&task->updates_lock);

	goto exit;
inval:
	ret = -EINVAL;
exit:
	task_put(task, &info->task_lock);
	return ret;
}

SYSCALL_DEFINE3(orbit_pull, struct orbit_result_kernel __user *, result, obid_t, gobid,
		unsigned long, taskid)
{
	return do_orbit_pull(result, gobid, taskid);
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
