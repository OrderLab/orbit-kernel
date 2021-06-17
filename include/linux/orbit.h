#ifndef __ORBIT_H__
#define __ORBIT_H__

#include <linux/compiler_types.h>

/* This struct is part of the task_struct.
 * For now, we only allow at most one orbit for each process.
 * The parent task_struct has a pointer to the child, and the child reuse the
 * same pointer to point to the parent. The is_orbit bit denotes whether the
 * process is an orbit. */
struct orbit_info;

extern struct task_struct *fork_to_orbit(const char __user *name,
					 void __user *argbuf);

struct orbit_info *orbit_create_info(const char __user *name,
				     void __user *argbuf);

#endif /* __ORBIT_H__ */
