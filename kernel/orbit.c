#include <asm/current.h>
#include <linux/orbit.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>

typedef (void*)(*obEntry)(void*);

/* The snapshot and zap part is copied and modified from memory.c */

static unsigned long zap_pte_range(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end,
				struct zap_details *details)
{
	struct mm_struct *mm = tlb->mm;
	int force_flush = 0;
	int rss[NR_MM_COUNTERS];
	spinlock_t *ptl;
	pte_t *start_pte;
	pte_t *pte;
	swp_entry_t entry;

	tlb_change_page_size(tlb, PAGE_SIZE);
again:
	init_rss_vec(rss);
	start_pte = pte_offset_map_lock(mm, pmd, addr, &ptl);
	pte = start_pte;
	flush_tlb_batched_pending(mm);
	arch_enter_lazy_mmu_mode();
	do {
		pte_t ptent = *pte;
		if (pte_none(ptent))
			continue;

		if (need_resched())
			break;

		if (pte_present(ptent)) {
			struct page *page;

			page = vm_normal_page(vma, addr, ptent);
			if (unlikely(details) && page) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping &&
				    details->check_mapping != page_rmapping(page))
					continue;
			}
			ptent = ptep_get_and_clear_full(mm, addr, pte,
							tlb->fullmm);
			tlb_remove_tlb_entry(tlb, pte, addr);
			if (unlikely(!page))
				continue;

			if (!PageAnon(page)) {
				if (pte_dirty(ptent)) {
					force_flush = 1;
					set_page_dirty(page);
				}
				if (pte_young(ptent) &&
				    likely(!(vma->vm_flags & VM_SEQ_READ)))
					mark_page_accessed(page);
			}
			rss[mm_counter(page)]--;
			page_remove_rmap(page, false);
			if (unlikely(page_mapcount(page) < 0))
				print_bad_pte(vma, addr, ptent, page);
			if (unlikely(__tlb_remove_page(tlb, page))) {
				force_flush = 1;
				addr += PAGE_SIZE;
				break;
			}
			continue;
		}

		entry = pte_to_swp_entry(ptent);
		if (non_swap_entry(entry) && is_device_private_entry(entry)) {
			struct page *page = device_private_entry_to_page(entry);

			if (unlikely(details && details->check_mapping)) {
				/*
				 * unmap_shared_mapping_pages() wants to
				 * invalidate cache without truncating:
				 * unmap shared but keep private pages.
				 */
				if (details->check_mapping !=
				    page_rmapping(page))
					continue;
			}

			pte_clear_not_present_full(mm, addr, pte, tlb->fullmm);
			rss[mm_counter(page)]--;
			page_remove_rmap(page, false);
			put_page(page);
			continue;
		}

		/* If details->check_mapping, we leave swap entries. */
		if (unlikely(details))
			continue;

		if (!non_swap_entry(entry))
			rss[MM_SWAPENTS]--;
		else if (is_migration_entry(entry)) {
			struct page *page;

			page = migration_entry_to_page(entry);
			rss[mm_counter(page)]--;
		}
		if (unlikely(!free_swap_and_cache(entry)))
			print_bad_pte(vma, addr, ptent, NULL);
		pte_clear_not_present_full(mm, addr, pte, tlb->fullmm);
	} while (pte++, addr += PAGE_SIZE, addr != end);

	add_mm_rss_vec(mm, rss);
	arch_leave_lazy_mmu_mode();

	/* Do the actual TLB flush before dropping ptl */
	if (force_flush)
		tlb_flush_mmu_tlbonly(tlb);
	pte_unmap_unlock(start_pte, ptl);

	/*
	 * If we forced a TLB flush (either due to running out of
	 * batch buffers or because we needed to flush dirty TLB
	 * entries before releasing the ptl), free the batched
	 * memory too. Restart if we didn't do everything.
	 */
	if (force_flush) {
		force_flush = 0;
		tlb_flush_mmu(tlb);
	}

	if (addr != end) {
		cond_resched();
		goto again;
	}

	return addr;
}


static inline unsigned long
snap_one_pte(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pte_t *dst_pte, pte_t *src_pte, struct vm_area_struct *vma,
		unsigned long addr, int *rss, struct mmu_gather *tlb)
{
	unsigned long vm_flags = vma->vm_flags;
	pte_t pte = *src_pte;
	struct page *page;

	/* pte contains position in swap or file, so copy. */
	if (unlikely(!pte_present(pte))) {
		/* The entry is not present and the same, nothing changed,
		 * just skip. */
		if (pte_same(*dst_pte, pte))
			return 0;

		swp_entry_t entry = pte_to_swp_entry(pte);

		if (likely(!non_swap_entry(entry))) {
			if (swap_duplicate(entry) < 0)
				return entry.val;

			/* make sure dst_mm is on swapoff's mmlist. */
			if (unlikely(list_empty(&dst_mm->mmlist))) {
				spin_lock(&mmlist_lock);
				if (list_empty(&dst_mm->mmlist))
					list_add(&dst_mm->mmlist,
							&src_mm->mmlist);
				spin_unlock(&mmlist_lock);
			}
			rss[MM_SWAPENTS]++;
		} else if (is_migration_entry(entry)) {
			page = migration_entry_to_page(entry);

			rss[mm_counter(page)]++;

			if (is_write_migration_entry(entry) &&
					is_cow_mapping(vm_flags)) {
				/*
				 * COW mappings require pages in both
				 * parent and child to be set to read.
				 */
				make_migration_entry_read(&entry);
				pte = swp_entry_to_pte(entry);
				if (pte_swp_soft_dirty(*src_pte))
					pte = pte_swp_mksoft_dirty(pte);
				set_pte_at(src_mm, addr, src_pte, pte);
			}
		} else if (is_device_private_entry(entry)) {
			page = device_private_entry_to_page(entry);

			/*
			 * Update rss count even for unaddressable pages, as
			 * they should treated just like normal pages in this
			 * respect.
			 *
			 * We will likely want to have some new rss counters
			 * for unaddressable pages, at some point. But for now
			 * keep things as they are.
			 */
			get_page(page);
			rss[mm_counter(page)]++;
			page_dup_rmap(page, false);

			/*
			 * We do not preserve soft-dirty information, because so
			 * far, checkpoint/restore is the only feature that
			 * requires that. And checkpoint/restore does not work
			 * when a device driver is involved (you cannot easily
			 * save and restore device driver state).
			 */
			if (is_write_device_private_entry(entry) &&
			    is_cow_mapping(vm_flags)) {
				make_device_private_entry_read(&entry);
				pte = swp_entry_to_pte(entry);
				set_pte_at(src_mm, addr, src_pte, pte);
			}
		}
		goto out_set_pte;
	} else if (pte_present(*dst_pte)) {
		/* Now src_pte and dst_pte are both present. */
		/* If both are clean, nothing changed, just skip. */
		if (!pte_dirty(pte) && pte_same(*dst_pte, pte))
			return 0;
	}

	/*
	 * If it's a COW mapping, write protect it both
	 * in the parent and the child
	 */
	if (is_cow_mapping(vm_flags) && pte_write(pte)) {
		ptep_set_wrprotect(src_mm, addr, src_pte);
		pte = pte_wrprotect(pte);
	}

	/*
	 * If it's a shared mapping, mark it clean in
	 * the child
	 */
	if (vm_flags & VM_SHARED)
		pte = pte_mkclean(pte);
	pte = pte_mkold(pte);

	page = vm_normal_page(vma, addr, pte);
	if (page) {
		get_page(page);
		page_dup_rmap(page, false);
		rss[mm_counter(page)]++;
	} else if (pte_devmap(pte)) {
		page = pte_page(pte);
	}

out_set_pte:
	/* TODO: zap old dst pte mapping, merge zap_pte_one() into snap_one_pte() */
	/* unsigned long ret = zap_pte_one(struct mmu_gather *tlb,
				struct vm_area_struct *vma, pmd_t *pmd,
				unsigned long addr, unsigned long end,
				NULL); */
	set_pte_at(dst_mm, addr, dst_pte, pte);
	return 0;
}

static int snap_pte_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		   pmd_t *dst_pmd, pmd_t *src_pmd, struct vm_area_struct *vma,
		   unsigned long addr, unsigned long end, struct mmu_gather *tlb)
{
	pte_t *orig_src_pte, *orig_dst_pte;
	pte_t *src_pte, *dst_pte;
	spinlock_t *src_ptl, *dst_ptl;
	int progress = 0;
	int rss[NR_MM_COUNTERS];
	swp_entry_t entry = (swp_entry_t){0};

again:
	init_rss_vec(rss);

	dst_pte = pte_alloc_map_lock(dst_mm, dst_pmd, addr, &dst_ptl);
	if (!dst_pte)
		return -ENOMEM;
	src_pte = pte_offset_map(src_pmd, addr);
	src_ptl = pte_lockptr(src_mm, src_pmd);
	spin_lock_nested(src_ptl, SINGLE_DEPTH_NESTING);
	orig_src_pte = src_pte;
	orig_dst_pte = dst_pte;
	arch_enter_lazy_mmu_mode();

	do {
		/*
		 * We are holding two locks at this point - either of them
		 * could generate latencies in another task on another CPU.
		 */
		if (progress >= 32) {
			progress = 0;
			if (need_resched() ||
			    spin_needbreak(src_ptl) || spin_needbreak(dst_ptl))
				break;
		}
		if (pte_none(*src_pte)) {
			progress++;
			continue;
		}
		entry.val = snap_one_pte(dst_mm, src_mm, dst_pte, src_pte,
							vma, addr, rss);
		if (entry.val)
			break;
		progress += 8;
	} while (dst_pte++, src_pte++, addr += PAGE_SIZE, addr != end);

	arch_leave_lazy_mmu_mode();
	spin_unlock(src_ptl);
	pte_unmap(orig_src_pte);
	add_mm_rss_vec(dst_mm, rss);
	pte_unmap_unlock(orig_dst_pte, dst_ptl);
	cond_resched();

	if (entry.val) {
		if (add_swap_count_continuation(entry, GFP_KERNEL) < 0)
			return -ENOMEM;
		progress = 0;
	}
	if (addr != end)
		goto again;
	return 0;
}

static inline int snap_pmd_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pud_t *dst_pud, pud_t *src_pud, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end, struct mmu_gather *tlb)
{
	pmd_t *src_pmd, *dst_pmd;
	unsigned long next;

	dst_pmd = pmd_alloc(dst_mm, dst_pud, addr);
	if (!dst_pmd)
		return -ENOMEM;
	src_pmd = pmd_offset(src_pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		if (is_swap_pmd(*src_pmd) || pmd_trans_huge(*src_pmd)
			|| pmd_devmap(*src_pmd)) {
			int err;
			VM_BUG_ON_VMA(next-addr != HPAGE_PMD_SIZE, vma);
			err = snap_huge_pmd(dst_mm, src_mm,
					    dst_pmd, src_pmd, addr, vma);
			if (err == -ENOMEM)
				return -ENOMEM;
			if (!err)
				continue;
			/* fall through */
		}
		if (pmd_none_or_clear_bad(src_pmd))
			continue;
		if (snap_pte_range(dst_mm, src_mm, dst_pmd, src_pmd,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pmd++, src_pmd++, addr = next, addr != end);
	return 0;
}

static inline int snap_pud_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		p4d_t *dst_p4d, p4d_t *src_p4d, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end, struct mmu_gather *tlb)
{
	pud_t *src_pud, *dst_pud;
	unsigned long next;

	dst_pud = pud_alloc(dst_mm, dst_p4d, addr);
	if (!dst_pud)
		return -ENOMEM;
	src_pud = pud_offset(src_p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		if (pud_trans_huge(*src_pud) || pud_devmap(*src_pud)) {
			int err;

			VM_BUG_ON_VMA(next-addr != HPAGE_PUD_SIZE, vma);
			err = snap_huge_pud(dst_mm, src_mm,
					    dst_pud, src_pud, addr, vma);
			if (err == -ENOMEM)
				return -ENOMEM;
			if (!err)
				continue;
			/* fall through */
		}
		if (pud_none_or_clear_bad(src_pud))
			continue;
		if (snap_pmd_range(dst_mm, src_mm, dst_pud, src_pud,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_pud++, src_pud++, addr = next, addr != end);
	return 0;
}

static inline int snap_p4d_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
		pgd_t *dst_pgd, pgd_t *src_pgd, struct vm_area_struct *vma,
		unsigned long addr, unsigned long end, struct mmu_gather *tlb)
{
	p4d_t *src_p4d, *dst_p4d;
	unsigned long next;

	dst_p4d = p4d_alloc(dst_mm, dst_pgd, addr);
	if (!dst_p4d)
		return -ENOMEM;
	src_p4d = p4d_offset(src_pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		if (p4d_none_or_clear_bad(src_p4d))
			continue;
		if (snap_pud_range(dst_mm, src_mm, dst_p4d, src_p4d,
						vma, addr, next))
			return -ENOMEM;
	} while (dst_p4d++, src_p4d++, addr = next, addr != end);
	return 0;
}

int snap_page_range(struct mm_struct *dst_mm, struct mm_struct *src_mm,
	struct vm_area_struct *vma, unsigned long addr, unsigned long end)
{
	pgd_t *src_pgd, *dst_pgd;
	unsigned long next;
	struct mmu_notifier_range range;
	bool is_cow;
	int ret;

	/* Variables to free up dst entries */
	struct mmu_gather tlb;

	lru_add_drain();
	tlb_gather_mmu(&tlb, dst_mm, addr, end);
	update_hiwater_rss(dst_mm);

	unmap_vmas(&tlb, vma, addr, end);

	/* Currently we assume that the range will only be in one vma.
	 * This check was also done in the orbit_call. Ideally, we will
	 * modify this function to allow memory range across multiple vmas. */
	if (!(vma->vm_start <= addr && end <= vma->vm_end))
		return -EINVAL;

	/* TODO: handle VM_HUGETLB | VM_PFNMAP | VM_MIXEDMAP */

	if (unlikely(vma->vm_flags & VM_PFNMAP)) {
		return -EINVAL;
		/*
		 * We do not free on error cases below as remove_vma
		 * gets called on error from higher level routine
		 */
		/* ret = track_pfn_copy(vma);
		if (ret)
			return ret; */
	}

	/* TODO: how is cow handled by default... */
	/*
	 * We need to invalidate the secondary MMU mappings only when
	 * there could be a permission downgrade on the ptes of the
	 * parent mm. And a permission downgrade will only happen if
	 * is_cow_mapping() returns true.
	 */
	is_cow = is_cow_mapping(vma->vm_flags);

	if (is_cow) {
		mmu_notifier_range_init(&range, MMU_NOTIFY_PROTECTION_PAGE,
					0, vma, src_mm, addr, end);
		mmu_notifier_invalidate_range_start(&range);
	}

	ret = 0;
	dst_pgd = pgd_offset(dst_mm, addr);
	src_pgd = pgd_offset(src_mm, addr);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(src_pgd))
			continue;
		if (unlikely(snap_p4d_range(dst_mm, src_mm, dst_pgd, src_pgd,
					    vma, addr, next))) {
			ret = -ENOMEM;
			break;
		}
	} while (dst_pgd++, src_pgd++, addr = next, addr != end);

	if (is_cow)
		mmu_notifier_invalidate_range_end(&range);

	tlb_finish_mmu(&tlb, addr, end);

	return ret;
}

struct orbit_task *orbit_create_task(void __user *arg,
				unsigned long start, unsigned long end)
{
	struct orbit_task *new_task;

	new_task = kmalloc(sizeof(struct orbit_task), GFP_KERNEL);
	if (new_task == NULL)
		return NULL;

	INIT_LIST_HEAD(&new_task->elem);
	sema_init(&new_task->finish);
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
	sema_init(&info->sem);
	mutex_init(&info->list_lock);
	info->orbit_task = NULL;
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

free_task:
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
	list_del(info->task_list->next);
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
	snap_page_range(ob->mm, parent->mm, vma,
			snap_page_start, snap_page_start + segment_length);

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
