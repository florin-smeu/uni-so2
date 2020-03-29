// SPDX-License-Identifier: GPL-2.0+

/*
 * tracer.c - Kprobe based tracer
 *
 * Author: Florin Smeu <florin.ion.smeu@gmail.com>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/miscdevice.h>
#include <linux/hashtable.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>

#include "tracer.h"

DEFINE_HASHTABLE(tr_hashtable, TRACER_HASH_BITS);
DEFINE_HASHTABLE(mem_hashtable, MEM_HASH_BITS);

DEFINE_SPINLOCK(tracer_spinlock);
DEFINE_SPINLOCK(mem_spinlock);

/*
 * Structure that holds information about a tracer record. The information is
 * stored per process.
 */
struct tr_record {
	pid_t pid;

	/* Accounting fields */
	atomic_t alloc_count;
	atomic_t free_count;
	atomic64_t alloc_mem;
	atomic64_t free_mem;
	atomic_t sched_count;
	atomic_t up_count;
	atomic_t down_count;
	atomic_t lock_count;
	atomic_t unlock_count;

	struct hlist_node next;
};

/*
 * Structure that holds information about the memory allocation. Useful when
 * a traced process performs memory operations, because it links the size and
 * the address of the memory allocated/freed.
 */
struct mem_record {
	pid_t pid;

	/* Size of the memory allocated */
	atomic64_t size;
	/* Address of the memory allocated */
	atomic64_t addr;

	struct hlist_node next;
};

/*
 * init_tracer_record - initialize the fields of a tracer record structure
 * @tr_info: &struct tr_record to be initialized
 * @pid: the pid to be used in initialization
 */
static void init_tracer_record(struct tr_record *tr_info, pid_t pid)
{
	tr_info->pid = pid;
	atomic_set(&tr_info->alloc_count, 0);
	atomic_set(&tr_info->free_count, 0);
	atomic64_set(&tr_info->alloc_mem, 0);
	atomic64_set(&tr_info->free_mem, 0);
	atomic_set(&tr_info->sched_count, 0);
	atomic_set(&tr_info->up_count, 0);
	atomic_set(&tr_info->down_count, 0);
	atomic_set(&tr_info->lock_count, 0);
	atomic_set(&tr_info->unlock_count, 0);
}

/*
 * delete_hashtable - deallocate memory occupied by a hashtable
 * @type: char representing the type of the hashtable
 */
static void delete_hashtable(char type)
{
	struct tr_record *tr_info;
	struct mem_record *mem_info;
	struct hlist_node *tmp;
	int bkt;

	if (type == TRACER_HASH_ID) {
		hash_for_each_safe(tr_hashtable, bkt, tmp, tr_info, next) {
			spin_lock(&tracer_spinlock);
			hash_del(&tr_info->next);
			kfree(tr_info);
			spin_unlock(&tracer_spinlock);
		}
	} else if (type == MEM_HASH_ID) {
		hash_for_each_safe(mem_hashtable, bkt, tmp, mem_info, next) {
			spin_lock(&mem_spinlock);
			hash_del(&mem_info->next);
			kfree(mem_info);
			spin_unlock(&mem_spinlock);
		}
	}
}

/**************************************************************
 * Procfs file data and operations
 */

struct proc_dir_entry *proc_tracer;

static int tracer_proc_show(struct seq_file *m, void *v)
{
	int bkt;
	struct tr_record *tr_info;

	seq_puts(m, "PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\tlock\tunlock\n");

	hash_for_each(tr_hashtable, bkt, tr_info, next) {
		seq_printf(m, "%d\t%d\t%d\t%lld\t%lld\t%d\t%d\t%d\t%d\t%d\n",
			   tr_info->pid,
			   atomic_read(&tr_info->alloc_count),
			   atomic_read(&tr_info->free_count),
			   atomic64_read(&tr_info->alloc_mem),
			   atomic64_read(&tr_info->free_mem),
			   atomic_read(&tr_info->sched_count),
			   atomic_read(&tr_info->up_count),
			   atomic_read(&tr_info->down_count),
			   atomic_read(&tr_info->lock_count),
			   atomic_read(&tr_info->unlock_count));
	}

	return 0;
}

static int tracer_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_proc_show, NULL);
}

static const struct file_operations tracer_fops = {
	.owner		= THIS_MODULE,
	.open		= tracer_read_open,
	.read		= seq_read,
	.release	= single_release,
};

/**************************************************************
 * Char device data and operations
 */

static long tracer_cdev_ioctl(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	struct tr_record *tr_info;
	struct mem_record *mem_info;
	struct hlist_node *tmp;

	pid_t pid = arg;

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		/*
		 * Add a process to the tr_hashtable.
		 */
		tr_info = kmalloc(sizeof(struct tr_record), GFP_ATOMIC);
		if (!tr_info)
			return -ENOMEM;

		init_tracer_record(tr_info, pid);

		spin_lock(&tracer_spinlock);
		hash_add(tr_hashtable, &tr_info->next, tr_info->pid);
		spin_unlock(&tracer_spinlock);
		break;
	case TRACER_REMOVE_PROCESS:
		/*
		 * Remove a process from the tr_hashtable. Also, make sure to
		 * free the memory occupied by the mem_hashtable.
		 */
		hash_for_each_possible_safe(tr_hashtable, tr_info, tmp,
					    next, pid) {
			if (pid == tr_info->pid) {
				spin_lock(&tracer_spinlock);
				hash_del(&tr_info->next);
				kfree(tr_info);
				spin_unlock(&tracer_spinlock);
			}
		}

		hash_for_each_possible_safe(mem_hashtable, mem_info, tmp,
					    next, pid) {
			if (pid == mem_info->pid) {
				spin_lock(&mem_spinlock);
				hash_del(&mem_info->next);
				kfree(mem_info);
				spin_unlock(&mem_spinlock);
			}
		}
	}

	return 0;
}

static const struct file_operations dev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = tracer_cdev_ioctl,
};

static struct miscdevice tracer_dev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &dev_fops,
};

/**************************************************************
 * Kprobes handlers and variables
 */

static int alloc_probe_entry_handler(struct kretprobe_instance *ri,
				     struct pt_regs *regs)
{
	struct tr_record *tr_info;
	pid_t pid;
	unsigned long *size;

	pid = current->pid;

	/*
	 * Store the size of the memory allocated in the current
	 * kretprobe instance data field.
	 */
	size = (unsigned long *)ri->data;
	*size = regs->ax;

	hash_for_each_possible(tr_hashtable, tr_info, next, pid) {
		if (pid == tr_info->pid) {
			atomic_inc(&tr_info->alloc_count);
			atomic64_add(*size, &tr_info->alloc_mem);
		}
	}

	return 0;
}

static int alloc_probe_return_handler(struct kretprobe_instance *ri,
				      struct pt_regs *regs)
{
	struct mem_record *mem_info;
	pid_t pid;
	unsigned long *size;
	unsigned long retval;

	/*
	 * Retrieve the size of the memory allocated from the data field of
	 * the current kretprobe instance.
	 */
	pid = current->pid;
	size = (unsigned long *)ri->data;

	/*
	 * Retrieve the address of the memory allocation.
	 */
	retval = regs_return_value(regs);

	mem_info = kmalloc(sizeof(struct mem_record), GFP_ATOMIC);
	if (!mem_info)
		return -ENOMEM;

	mem_info->pid = pid;
	atomic64_set(&mem_info->size, *size);
	atomic64_set(&mem_info->addr, retval);

	spin_lock(&mem_spinlock);
	hash_add(mem_hashtable, &mem_info->next, mem_info->pid);
	spin_unlock(&mem_spinlock);

	return 0;
}

static int kfree_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tr_record *tr_info;
	struct mem_record *mem_info;
	pid_t pid;
	unsigned long addr;
	unsigned long size = 0;

	pid = current->pid;
	addr = regs->ax;

	/*
	 * Retrieve the size of the memory allocated by inspecting the
	 * mem_hashtable.
	 */
	hash_for_each_possible(mem_hashtable, mem_info, next, pid) {
		if (pid == mem_info->pid) {
			if (addr == atomic64_read(&mem_info->addr)) {
				size = atomic64_read(&mem_info->size);
				break;
			}
		}
	}

	hash_for_each_possible(tr_hashtable, tr_info, next, pid) {
		if (pid == tr_info->pid) {
			atomic_inc(&tr_info->free_count);
			atomic64_add(size, &tr_info->free_mem);
		}
	}

	return 0;
}

static int sched_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tr_record *tr_info;
	pid_t pid;

	pid = current->pid;

	hash_for_each_possible(tr_hashtable, tr_info, next, pid) {
		if (pid == tr_info->pid)
			atomic_inc(&tr_info->sched_count);
	}

	return 0;
}

static int up_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tr_record *tr_info;
	pid_t pid;

	pid = current->pid;

	hash_for_each_possible(tr_hashtable, tr_info, next, pid) {
		if (pid == tr_info->pid)
			atomic_inc(&tr_info->up_count);
	}

	return 0;
}

static int down_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tr_record *tr_info;
	pid_t pid;

	pid = current->pid;

	hash_for_each_possible(tr_hashtable, tr_info, next, pid) {
		if (pid == tr_info->pid)
			atomic_inc(&tr_info->down_count);
	}

	return 0;
}

static int lock_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tr_record *tr_info;
	pid_t pid;

	pid = current->pid;

	hash_for_each_possible(tr_hashtable, tr_info, next, pid) {
		if (pid == tr_info->pid)
			atomic_inc(&tr_info->lock_count);
	}

	return 0;
}

static int unlock_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tr_record *tr_info;
	pid_t pid;

	pid = current->pid;

	hash_for_each_possible(tr_hashtable, tr_info, next, pid) {
		if (pid == tr_info->pid)
			atomic_inc(&tr_info->unlock_count);
	}

	return 0;
}

static int exit_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct tr_record *tr_info;
	struct mem_record *mem_info;
	struct hlist_node *tmp;
	pid_t pid;

	pid = current->pid;

	/*
	 * Delete hash entries and deallocate memory when a process finishes
	 * execution. This is signaled by the do_exit() call.
	 */
	hash_for_each_possible_safe(tr_hashtable, tr_info, tmp, next, pid) {
		if (pid == tr_info->pid) {
			spin_lock(&tracer_spinlock);
			hash_del(&tr_info->next);
			kfree(tr_info);
			spin_unlock(&tracer_spinlock);
		}
	}

	hash_for_each_possible_safe(mem_hashtable, mem_info, tmp, next, pid) {
		if (pid == mem_info->pid) {
			spin_lock(&mem_spinlock);
			hash_del(&mem_info->next);
			kfree(mem_info);
			spin_unlock(&mem_spinlock);
		}
	}

	return 0;
}

static struct kretprobe alloc_probe = {
	.kp.symbol_name = "__kmalloc",
	.entry_handler = alloc_probe_entry_handler,
	.handler = alloc_probe_return_handler,
	.maxactive = 32,
	.data_size = sizeof(unsigned long),
};

static struct kprobe kfree_probe = {
	.symbol_name = "kfree",
	.pre_handler = kfree_probe_handler,
};

static struct kprobe sched_probe = {
	.symbol_name = "schedule",
	.pre_handler = sched_probe_handler,
};

static struct kprobe up_probe = {
	.symbol_name = "up",
	.pre_handler = up_probe_handler,
};

static struct kprobe down_probe = {
	.symbol_name = "down_interruptible",
	.pre_handler = down_probe_handler,
};

static struct kprobe lock_probe = {
	.symbol_name = "mutex_lock_nested",
	.pre_handler = lock_probe_handler,
};

static struct kprobe unlock_probe = {
	.symbol_name = "mutex_unlock",
	.pre_handler = unlock_probe_handler,
};

static struct kprobe exit_probe = {
	.symbol_name = "do_exit",
	.pre_handler = exit_probe_handler,
};

/**************************************************************
 * Module init and exit functions
 */

static int tracer_init(void)
{
	int ret;

	hash_init(tr_hashtable);
	hash_init(mem_hashtable);

	spin_lock_init(&tracer_spinlock);
	spin_lock_init(&mem_spinlock);

	proc_tracer = proc_create(PROCFS_FILE, 0000, NULL, &tracer_fops);
	if (!proc_tracer)
		return -ENOMEM;

	ret = misc_register(&tracer_dev);
	if (ret)
		goto remove_procfs_entry;

	ret = register_kretprobe(&alloc_probe);
	if (ret)
		goto deregister_miscdevice;

	ret = register_kprobe(&kfree_probe);
	if (ret)
		goto unregister_alloc_probe;

	ret = register_kprobe(&exit_probe);
	if (ret)
		goto unregister_kfree_probe;

	ret = register_kprobe(&sched_probe);
	if (ret)
		goto unregister_exit_probe;

	ret = register_kprobe(&up_probe);
	if (ret)
		goto unregister_sched_probe;

	ret = register_kprobe(&down_probe);
	if (ret)
		goto unregister_up_probe;

	ret = register_kprobe(&lock_probe);
	if (ret)
		goto unregister_down_probe;

	ret = register_kprobe(&unlock_probe);
	if (ret)
		goto unregister_lock_probe;

	return 0;

unregister_lock_probe:
	unregister_kprobe(&lock_probe);
unregister_down_probe:
	unregister_kprobe(&down_probe);
unregister_up_probe:
	unregister_kprobe(&up_probe);
unregister_sched_probe:
	unregister_kprobe(&sched_probe);
unregister_exit_probe:
	unregister_kprobe(&exit_probe);
unregister_kfree_probe:
	unregister_kprobe(&kfree_probe);
unregister_alloc_probe:
	unregister_kretprobe(&alloc_probe);

deregister_miscdevice:
	misc_deregister(&tracer_dev);

remove_procfs_entry:
	proc_remove(proc_tracer);

	return -1;
}

static void tracer_exit(void)
{
	unregister_kretprobe(&alloc_probe);
	unregister_kprobe(&kfree_probe);
	unregister_kprobe(&exit_probe);
	unregister_kprobe(&sched_probe);
	unregister_kprobe(&up_probe);
	unregister_kprobe(&down_probe);
	unregister_kprobe(&lock_probe);
	unregister_kprobe(&unlock_probe);

	misc_deregister(&tracer_dev);
	proc_remove(proc_tracer);

	delete_hashtable(TRACER_HASH_ID);
	delete_hashtable(MEM_HASH_ID);
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Florin Smeu <florin.ion.smeu@gmail.com");
MODULE_LICENSE("GPL v2");
