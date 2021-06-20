#ifndef __ORBIT_H__
#define __ORBIT_H__

#include <linux/types.h>
#include <linux/compiler_types.h>

/* This struct is part of the task_struct. The is_orbit bit denotes whether the
 * process is an orbit.
 *
 * One process can have multiple orbits. The task_struct has an additional
 * orbit_children list that stores the list of orbit tasks. The specific
 * orbit of a process can be either identified by a tuple of <main_pid,
 * local_obid> or <global_obid>.
 */
struct orbit_info;

extern struct task_struct *fork_to_orbit(const char __user *name,
					 void __user *argbuf);

struct orbit_info *orbit_create_info(const char __user *name,
				     void __user *argbuf);

struct orbit_info *find_orbit_by_gobid(obid_t gobid,
				       struct task_struct **orbit);

bool signal_orbit_exit(struct task_struct *ob);

#endif /* __ORBIT_H__ */
