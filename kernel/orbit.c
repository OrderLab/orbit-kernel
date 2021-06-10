#include <linux/orbit.h>
#include <linux/mm.h>
#include <linux/mman.h>
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

#include <linux/timekeeping.h>
#include <linux/timex.h>

#define DBG 0

#define printd if(DBG)printk

#define whatis(x) printd(#x " is %lu\n", x)

#if DBG == 1
	#define internalreturn long __attribute__((optimize("O0")))
#else
	#define internalreturn static long /* __attribute__((always_inline)) */
#endif

typedef void*(*orbit_entry)(void*);

/* Orbit flags */
#define ORBIT_ASYNC		1	/* Whether the call is async */
#define ORBIT_NORETVAL		2	/* Whether we want the return value.
					 * This option is ignored in async. */

/* FIXME: `start` and `end` should be platform-independent (void __user *)? */
struct pool_range {
	unsigned long start;
	unsigned long end;
	bool cow;
};

/* Duplicated struct definition, should be eventually moved to mm.h */
struct vma_snapshot {
	size_t count;
	size_t head, tail;	/* Cursor in the first and last snap_block */
	struct list_head list;
};

void snap_init(struct vma_snapshot *snap);
void snap_destroy(struct vma_snapshot *snap);

struct pool_snapshot {
	unsigned long start, end;
	bool cow;
	struct vma_snapshot snapshot;
	char *data;
};

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
	size_t			argsize;
	unsigned long		retval;

	struct mutex		updates_lock;	/* lock for update list */
	struct semaphore	updates_sem;
	/* List of updates to be applied
	 * FIXME: Currently this is shared between update and update_v */
	struct list_head	updates;

	/* Memory ranges snapshotted. Variable-sized struct. */
	size_t			npool;
	struct pool_snapshot	pools[];

	/* Extra field: char arg_data[] starting at (char*)(pools + npool),
	 * see orbit_create_task. */
} __randomize_layout;

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

static struct orbit_task *orbit_create_task(
	unsigned long flags, void __user *arg, size_t argsize,
	size_t npool, struct pool_range __user * pools)
{
	struct orbit_task *new_task;
	size_t i;

	new_task = kmalloc(sizeof(*new_task) + argsize +
			npool * sizeof(struct pool_snapshot), GFP_KERNEL);
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
	new_task->argsize = argsize;
	new_task->taskid = 0;	/* taskid will be allocated later */
	new_task->flags = flags;

	new_task->npool = npool;
	/* TODO: check error of get_user */
	for (i = 0; i < npool; ++i) {
		get_user(new_task->pools[i].start, &pools[i].start);
		get_user(new_task->pools[i].end, &pools[i].end);
		get_user(new_task->pools[i].cow, &pools[i].cow);
		/* Initialize new_task->pools[i].
		 * Actual marking is done later in orbit_call. */
		snap_init(&new_task->pools[i].snapshot);
		new_task->pools[i].data = NULL;
	}

	/* TODO: check error of copy_from_user */
	copy_from_user(new_task->pools + npool, arg, argsize);

	return new_task;
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

struct orbit_info *orbit_create_info(void __user **argptr)
{
	struct orbit_info *info;

	timing_reference();

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

static int snapshot_share(struct mm_struct *dst_mm, struct mm_struct *src_mm,
	unsigned long addr);

enum { COUNTER_BASE = __COUNTER__ };

#define CKPT 0

#define ckpt(s) \
	do { if(CKPT) { \
		int cnt = __COUNTER__ - COUNTER_BASE - 1; \
		if (cnt == 0) { \
			ckpts[0] = (struct ckpt_t) { \
				.clk = get_cycles(), \
				.t = ktime_get_ns(), \
				.name = s, \
			}; \
		} else { \
			ckpts[cnt].clk += get_cycles() - ckpts[0].clk; \
			ckpts[cnt].t += ktime_get_ns() - ckpts[0].t; \
			ckpts[cnt].name = s; \
		} \
	} } while (0)

/* FIXME: Currently we send a task to the orbit, and let the orbit child to
 * create a snapshot actively. When should the snapshot timepoint happen?
 * Should it be right after the orbit call? If so, we may need to wait for the
 * orbit to finish its last task. */

/* Return value: In sync mode, this call returns the checker's return value.
 * In async mode, this returns a taskid integer. */
internalreturn orbit_call_internal(
	unsigned long flags, unsigned long obid,
	size_t npool, struct pool_range __user * pools,
	void __user * arg, size_t argsize)
{
	struct task_struct *ob, *parent;
	struct vm_area_struct *ob_vma, *parent_vma;
	struct orbit_info *info;
	struct orbit_task *new_task;
	unsigned long ret;
	size_t i;

	static u64 last_ns = 0;
	if (CKPT && last_ns == 0)
		last_ns = ktime_get_ns();

	static int tcnt = 0;
	static struct ckpt_t {
		cycles_t clk;
		u64 t;
		const char *name;
	} ckpts[32] = { { 0, 0, NULL, }, };

	ckpt("init");

	/* 1. Find the orbit context by obid, currently we only support one
	 * orbit entity per process, thus we will ignore the obid. */
	parent = current->group_leader;
	ob = parent->orbit_child;
	info = ob->orbit_info;

	/* 2. Create a orbit task struct and add to the orbit's task queue. */
	new_task = orbit_create_task(flags, arg, argsize, npool, pools);
	if (new_task == NULL)
		return -ENOMEM;

	ckpt("create_task");

	printd("arg = %p, new_task->arg = %p\n", arg, new_task->arg);

	/* Serialized marking protected parent mmap_sem.
	 * We do not allow parallel snapshotting in current design. */
	/* if (down_write_killable(&parent->mm->mmap_sem)) { */
	if (down_read_killable(&parent->mm->mmap_sem)) {
		ret = -EINTR;
		panic("orbit call cannot acquire parent sem");
	}

	ckpt("down_mmap_sem");

#if 1
	/* WON'T FIX: If you found weirdly high latency in CKPT for "begin-cow",
	 * changing snapshot order may help. This is because ckpt macro
	 * uses COUNTER macro and it subtracts from "after-down" instead
	 * of "down_mmap_sem". */
	/* for (i = npool; i--; ) { */
	for (i = 0; i < npool; ++i) {
		struct pool_snapshot *pool = new_task->pools + i;

		parent_vma = find_vma(parent->mm, pool->start);

		printd("pool %ld size %ld", i, pool->end - pool->start);
		/* TODO: kernel rules for cow */
		/* if (pool->end - pool->start <= 8192) { */
		if (!pool->cow) {
			size_t pool_size = pool->end - pool->start;
			if (pool_size == 0) {
				pool->data = NULL;
				continue;
			}
			ckpt("before-vmalloc");
			pool->data = vmalloc(pool_size);
			if (pool->data) {
				printd("Orbit allocated %ld\n", pool_size);
			} else {
				printk("Orbit OOM %ld\n", pool_size);
				panic("Orbit OOM");
			}
			ckpt("before-up");
			up_read(&parent->mm->mmap_sem);
			ckpt("begin-copy");
			copy_from_user(pool->data, (const void __user *)pool->start,
				pool_size);
			ckpt("end-copy");
			printd("copied\n");
			if (down_read_killable(&parent->mm->mmap_sem))
				panic("down failed");
			ckpt("after-down");
		} else if (0 && list_empty(&info->task_list)) {
			/* FIXME: we need ob lock */
			ob_vma = find_vma(ob->mm, pool->start);
			ret = update_page_range(ob->mm, parent->mm,
				ob_vma, parent_vma,
				pool->start, pool->end,
				ORBIT_UPDATE_SNAPSHOT, NULL);
		} else {
			ckpt("begin-cow");
			ret = update_page_range(NULL, parent->mm,
				NULL, parent_vma,
				pool->start, pool->end,
				ORBIT_UPDATE_MARK, &pool->snapshot);
			ckpt("end-cow");
		}
	}
#else
	/* u64 t = ktime_get_ns();
	while (ktime_get_ns() - t < 26000)
		; */
#endif

	ckpt("do_snap");

	/* up_write(&parent->mm->mmap_sem); */
	up_read(&parent->mm->mmap_sem);
	ckpt("up-sem");

	/* Add task to the queue */
	/* TODO: make killable? */
	mutex_lock(&info->task_lock);
	ckpt("task-lock");

	/* Allocate taskid; valid taskid starts from 1 */
	/* TODO: will this overflow? */
	new_task->taskid = ++info->taskid_counter;
	list_add_tail(&new_task->elem, &info->task_list);
	if (info->next_task == NULL)
		info->next_task = new_task;
	ckpt("task-push");
	mutex_unlock(&info->task_lock);
	ckpt("task-unlock");
	up(&info->sem);
	ckpt("task-upsem");
	/* end push task */

	if (CKPT) {
		int total = __COUNTER__ - COUNTER_BASE - 1;
		++tcnt;

		if (tcnt % 100000 == 0) {

		u64 new_time = ktime_get_ns();
		printk("orbit_call 100000 times interval %lld ns\n", new_time - last_ns);
		last_ns = new_time;

		printk("orbit_call total %llu ns, %llu cycles\n",
			ckpts[total - 1].t / tcnt, ckpts[total - 1].clk / tcnt);

		ckpts[0].t = 0;
		ckpts[0].clk = 0;
		for (i = 1; i < total; ++i) {
			printk("CKPT %20s takes: %10llu ns, %10llu cycles\n",
				ckpts[i].name, (ckpts[i].t - ckpts[i - 1].t) / tcnt,
				(ckpts[i].clk - ckpts[i - 1].clk) / tcnt);
		}

		}
	}

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

SYSCALL_DEFINE6(orbit_call, unsigned long, flags,
		unsigned long, obid,
		size_t, npool,
		struct pool_range __user *, pools,
		void __user *, arg,
		size_t, argsize)
{
	return orbit_call_internal(flags, obid, npool, pools, arg, argsize);
}

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

SYSCALL_DEFINE1(orbit_send, const struct orbit_update_user __user *, update)
{
	return orbit_send_internal(update);
}

/* Return value: 0 for success, other value for failure */
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

SYSCALL_DEFINE3(orbit_recv, unsigned long, obid,
		unsigned long, taskid,
		struct orbit_update_user __user *, update_user)
{
	return orbit_recv_internal(obid, taskid, update_user);
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
	struct orbit_task *task;	/* Both old and new task. */
	struct vm_area_struct *ob_vma;
	struct pool_snapshot *pool;

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

		printd("orbit return locking\n");
		mutex_lock(&info->task_lock);
		printd("orbit return locked\n");

		info->next_task = list_is_last(&task->elem, &info->task_list) ?
					NULL : list_next_entry(task, elem);

		if (task->flags & ORBIT_ASYNC) {
			/* If the user does not want output,
			 * dec refcount and try to cleanup.
			 * Orbit_recv function will also try to cleanup.
			 */
			if (task->flags & ORBIT_NORETVAL) {
				up(&task->finish);
				if (refcount_read(&task->refcount) == 0 &&
					down_trylock(&task->finish) == 0)
				{
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

		mutex_unlock(&info->task_lock);
		printd("orbit return unlocked\n");
	}

	/* Second half: handle the next task */

	/* 1. Wait for a task to come in */
	/* TODO: make killable? */
	printd("orbit return down\n");
	down(&info->sem);
	printd("orbit return downed\n");
	mutex_lock(&info->task_lock);
	printd("orbit return locked 2\n");
	info->current_task = task = info->next_task;
	info->next_task = list_is_last(&task->elem, &info->task_list) ?
					NULL : list_next_entry(task, elem);

#if 0
	static int max_qdepth = 0;
	int qdepth = info->taskid_counter - task->taskid;
	if (qdepth > 100) {
		printk("warning: orbit list size %d\n", qdepth);
	}
	if (qdepth > max_qdepth) {
		max_qdepth = qdepth;
		printk("new max qdepth %d\n", max_qdepth);
	}
#endif

	mutex_unlock(&info->task_lock);
	printd("orbit return unlocked 2\n");

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
			panic("orbit error handling unimplemented!");
		}
		/* TODO: Update orbit vma list */
		/* Copy page range */
#if DBG
		panic("orbit cannot use parent_vma in debug mode");
		/* copy_page_range(ob->mm, parent->mm, parent_vma); */
#else
		/* FIXME: snapshot_share does not work with implicit vma_share */
		/* if (!(ob_vma->vm_start <= pool->start &&
			pool->end <= ob_vma->vm_start))
			snapshot_share(ob->mm, parent->mm, parent_vma); */

		printd("orbit apply pool %ld %d %ld\n", pool - task->pools, !!pool->data, pool->snapshot.count);
		printd("snapshot pte count is %ld\n", pool->snapshot.count);
		if (pool->data) {
			printd("access_ok %ld\n", access_ok(pool->start, pool->end - pool->start));
			/* up_write(&ob->mm->mmap_sem); */
			int ret = copy_to_user((void __user *)pool->start, pool->data,
				pool->end - pool->start);
			/* if (down_write_killable(&ob->mm->mmap_sem))
				panic("down failed"); */
			printd("orbit apply data success %d\n", ret);
			vfree(pool->data);
			printd("orbit apply freed\n");
			pool->data = NULL;
		} else if (pool->snapshot.count != 0)
			update_page_range(ob->mm, NULL, ob_vma, NULL,
				pool->start, pool->end, ORBIT_UPDATE_APPLY,
				&pool->snapshot);
		printd("snapshot pte count left %ld", pool->snapshot.count);
		snap_destroy(&pool->snapshot);
#endif
	}

	/* up_write(&ob->mm->mmap_sem); */
	up_read(&ob->mm->mmap_sem);
	printd("orbit apply up\n");

	/* 3. Setup the user argument to call entry_func.
	 * Current implementation is that the user runtime library passes
	 * a pointer to the arg (void **) to the orbit_create call.
	 * Upon each orbit_call, the father passes a argument pointer to the
	 * syscall. The kernel will write the pointer to the arg pointer.
	 * TODO: For now we require the argument to be stored in the snapshotted
	 * memory region.
	 */
	printd("task->arg = %p, info->argptr = %p\n", task->arg, info->argptr);
	/* TODO: check error of copy_to_user */
	copy_to_user(task->arg, task->pools + task->npool, task->argsize);
	put_user(task->arg, info->argptr);

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
	struct orbit_task *task;	/* Both old and new task. */
	struct vm_area_struct *ob_vma, *parent_vma;
	int ret;
	struct pool_snapshot *pool;

	if (!current->is_orbit)
		return -EINVAL;

	ob = current;
	parent = ob->orbit_child;	/* Currntly orbit_child in orbit is
					 * reused as a pointer to parent. */
	info = ob->orbit_info;

	task = info->current_task;

	for (pool = task->pools; pool < task->pools + task->npool; ++pool) {
		ob_vma = find_vma(ob->mm, pool->start);
		parent_vma = find_vma(parent->mm, pool->start);
		ret = update_page_range(parent->mm, ob->mm,
			parent_vma, ob_vma, pool->start, pool->end,
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
	size_t count;	/* Number of elements */
};

union orbit_result {
	unsigned long retval;
	struct orbit_scratch scratch;
};

struct orbit_update_v {
	struct list_head		elem;
	struct orbit_scratch		userdata;
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
	struct orbit_task *current_task;	/* Both old and new task. */
	struct vm_area_struct *ob_vma, *parent_vma;
	int ret = 0;
	struct orbit_update_v *new_update;
	unsigned long scratch_start, scratch_end;

	if (!current->is_orbit)
		return -EINVAL;

	ob = current;
	parent = ob->orbit_child;	/* Currently orbit_child in orbit is
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

	scratch_start = (unsigned long)new_update->userdata.ptr;
	scratch_end = scratch_start + new_update->userdata.size_limit;

	/* FIXME: synchronization */
	ob_vma = find_vma(ob->mm, scratch_start);
	parent_vma = find_vma(parent->mm, scratch_start);
	ret = update_page_range(parent->mm, ob->mm, parent_vma, ob_vma,
		scratch_start, scratch_end,
		ORBIT_UPDATE_SNAPSHOT, NULL);

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

/* Returns 1 on success. Returns 0 on end of updates. Returns -ERR on error. */
internalreturn do_orbit_recvv(union orbit_result __user *result,
			      unsigned long taskid)
{
	struct task_struct *ob, *parent;
	struct orbit_info *info;
	struct orbit_task *task;	/* Both old and new task. */
	struct orbit_update_v *update;
	int ret;
	struct list_head *iter;
	int found = 0;
	int list_count = 0;

	parent = current->group_leader;
	ob = parent->orbit_child;

	info = ob->orbit_info;

	task = info->current_task;

	/* TODO: maybe use rbtree along with the list? */
	mutex_lock(&info->task_lock);
	list_for_each(iter, &info->task_list) {
		++list_count;
		task = list_entry(iter, struct orbit_task, elem);
		if (task->taskid == taskid) {
			found = 1;
			break;
		}
	}
	mutex_unlock(&info->task_lock);

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
		put_user(task->retval, &result->retval);
		/* TODO: cleanup the task */
		ret = 0;	/* End of updates. */
	} else {
		update = list_first_entry(&task->updates, struct orbit_update_v, elem);
		list_del(&update->elem);

		/* TODO: check return value of copy */
#if DBG
		memcpy(&result->scratch, &update->userdata, sizeof(struct orbit_scratch));
#else
		copy_to_user(&result->scratch, &update->userdata, sizeof(struct orbit_scratch));
#endif
		kfree(update);

		ret = 1;
	}
	mutex_unlock(&task->updates_lock);

	/* ARC free task object */
	/* if (ret == 0 && refcount_dec_and_test(&task->refcount) == 1 &&
		down_trylock(&task->finish) == 0) */
	if (ret == 0 && down_trylock(&task->finish) == 0)
	{
		mutex_lock(&info->task_lock);
		list_del(&task->elem);
		mutex_unlock(&info->task_lock);
		kfree(task);
	}

	return ret;
}

SYSCALL_DEFINE2(orbit_recvv, union orbit_result __user *, result,
		unsigned long, taskid)
{
	return do_orbit_recvv(result, taskid);
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
	ret = snapshot_share(current->orbit_child->mm, current->mm, area);
	/* How to handle ret? */
	printd("snapshot_share returns %d", ret);

	return area;
}

SYSCALL_DEFINE3(orbit_mmap, unsigned long, addr, unsigned long, len,
		int, is_scratch)
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
	if (mpnt == NULL) panic("mpnt is NULL!");
	if (mpnt->vm_start != addr)
		panic("mpnt->vm_start %lx, addr %lx", mpnt->vm_start, addr);

	/* Check that dst has the same free area.
	 * This can be potentially skipped if we allow snapshot at different
	 * addresses in main program and orbit. */
	dst_near = find_vma(dst_mm, addr);
	printd("mpnt->vm_end %lx dst_near->vm_start %lx",
		mpnt->vm_end, dst_near->vm_start);
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
