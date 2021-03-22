#ifndef __ORBIT_H__
#define __ORBIT_H__

/* This struct is part of the task_struct.
 * For now, we only allow at most one orbit for each process.
 * The parent task_struct has a pointer to the child, and the child reuse the
 * same pointer to point to the parent. The is_orbit bit denotes whether the
 * process is an orbit. */
struct orbit_info;

struct orbit_info *orbit_create_info(void __user **argptr);

#endif /* __ORBIT_H__ */
