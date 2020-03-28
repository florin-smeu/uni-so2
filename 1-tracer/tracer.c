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
#include "tracer.h"


/*****************************************************************
 * Hashtable info
 */
struct mem_info {
	int pid;

	unsigned long addr;
	unsigned long size;

	struct hlist_node next;
};

/*
 * instrumentation record structure
 */
struct instr_rec {
	int pid;
	int alloc;
	int free;
	unsigned long alloc_mem;
	unsigned long free_mem;
	int sched;
	int up;
	int down;
	int lock;
	int unlock;

	spinlock_t s_lock;
	struct hlist_node next;
};

DEFINE_HASHTABLE(tr_hashtable, TRACER_HASH_BITS);
DEFINE_HASHTABLE(mi_hashtable, TRACER_HASH_BITS);

static void delete_hashtable(char type)
{
	struct instr_rec *data;
	struct mem_info *mi_record;
	
	struct hlist_node *tmp;
	int bkt;
	
	if (type == 't') {
		hash_for_each_safe(tr_hashtable, bkt, tmp, data, next) {
			hash_del(&data->next);
			kfree(data);
		}
	} else if (type == 'm') {
		hash_for_each_safe(mi_hashtable, bkt, tmp, mi_record, next) {
			hash_del(&mi_record->next);
			kfree(mi_record);
		}
	}
}


/*****************************************************************
 * Procfs file info
 */
struct proc_dir_entry *proc_tracer;

/*
 * tracer_proc_show - Print the tracer information
 */
static int tracer_proc_show(struct seq_file *m, void *v)
{
	int bkt;
	struct instr_rec *crt;

	seq_puts(m, "PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup"
			"\tdown\tlock\tunlock\n");

	hash_for_each(tr_hashtable, bkt, crt, next) {
		seq_printf(m, "%d\t%d\t%d\t\t%ld\t\t%ld\t%d\t%d\t%d\t%d\t%d\n", 
				crt->pid,
				crt->alloc, 
				crt->free,
				crt->alloc_mem,
				crt->free_mem,
				crt->sched,
				crt->up,
				crt->down,
				crt->lock,
				crt->unlock);
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


/*****************************************************************
 * Char device data and operations
 */
static int tracer_cdev_open(struct inode *inode, struct file *file)
{
	pr_info("Device open\n");
	return 0;
}

static int tracer_cdev_release(struct inode *inode, struct file *file)
{
	pr_info("Device release\n");
	return 0;
}

static ssize_t tracer_cdev_read(struct file *file,
					char __user *user_buffer,
					size_t size, loff_t *offset)
{
	pr_info("Device read\n");
	return 0;
}

static ssize_t tracer_cdev_write(struct file *file,
					const char __user *user_buffer,
					size_t size, loff_t *offset)
{
	pr_info("Device write\n");
	return 0;
}

static void init_instrumentation_record(struct instr_rec *data, int pid)
{
	data->pid = pid;
	data->alloc = 0;
	data->free = 0;
	data->alloc_mem = 0;
	data->free_mem = 0;
	data->sched = 0;
	data->up = 0;
	data->down = 0;
	data->lock = 0;
	data->unlock = 0;

	spin_lock_init(&data->s_lock);
}


static long tracer_cdev_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct instr_rec *data;
	struct hlist_node *tmp;
	
	pr_info("Device ioctl\n");

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pr_info("Add process %ld\n", arg);
		data = kmalloc(sizeof(struct instr_rec), GFP_ATOMIC);
		if (!data) {
			pr_err("Failed to allocate memory!\n");
			return -ENOMEM;
		}

		init_instrumentation_record(data, arg);
		hash_add(tr_hashtable, &data->next, data->pid);
		break;
	case TRACER_REMOVE_PROCESS:
		pr_info("Remove process %ld\n", arg);
		
		hash_for_each_possible_safe(tr_hashtable, data, tmp, next, arg) {
			if (arg == data->pid) {
				hash_del(&data->next);
				kfree(data);
			}
		}
		break;
	}
	return 0;
}

static const struct file_operations dev_fops = {                                
        .owner		= THIS_MODULE,                                                   
        .open		= tracer_cdev_open,                                                  
        .release 	= tracer_cdev_release,                                            
        .read 		= tracer_cdev_read,                                                  
        .write 		= tracer_cdev_write,                                                
        .unlocked_ioctl = tracer_cdev_ioctl                                        
}; 

static struct miscdevice tracer_dev = {	
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &dev_fops,
};

/*****************************************************************
 * Kretprobes data
 */

static int alloc_probe_entry_handler(struct kretprobe_instance *ri,
					struct pt_regs *regs)
{
	struct instr_rec *data;
	int pid;

	pid = current->pid;
	
	hash_for_each_possible(tr_hashtable, data, next, pid) {
		if (pid == data->pid) {
			spin_lock(&data->s_lock);
			data->alloc++;
			spin_unlock(&data->s_lock);
		}
	}
	
	/* Save the size of the memory allocated in the kretprobe_instance */
	memcpy(&ri->data, &regs->ax, sizeof(unsigned long));

	return 0;
}


static int alloc_probe_handler(struct kretprobe_instance *ri,
				struct pt_regs *regs)
{
        struct instr_rec *data;
	struct mem_info *mi_record;
	int pid;

	pid = current->pid;

	/* Add mem_info record in the hashtable */
	mi_record = kmalloc(sizeof(struct mem_info), GFP_ATOMIC);
	if (!mi_record)
		return -ENOMEM;

	mi_record->pid = pid;
	mi_record->addr = (unsigned long)ri->ret_addr;
	mi_record->size = (unsigned long)ri->data;
	hash_add(mi_hashtable, &mi_record->next, mi_record->pid);
	
	hash_for_each_possible(tr_hashtable, data, next, pid) {
		if (pid == data->pid) {
			spin_lock(&data->s_lock);
			data->alloc_mem += mi_record->size;
			spin_unlock(&data->s_lock);
		}
	}
	
        return 0; 
}

static int free_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
        struct instr_rec *data;
	struct mem_info *mi_record;
	int pid;
	unsigned long addr;
	unsigned long size;

	pid = current->pid;
	addr = regs->ax;

	size = 0;
	hash_for_each_possible(mi_hashtable, mi_record, next, pid) {
		if (pid == mi_record->pid && addr == mi_record->addr)
			size = mi_record->size;
	}

	if (!size)
		return -1;

	hash_for_each_possible(tr_hashtable, data, next, pid) {
		if (pid == data->pid) {
			spin_lock(&data->s_lock);
			data->free++;
			data->free_mem += size;
			spin_unlock(&data->s_lock);
		}
	}
        return 0; 
}


static int sched_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct instr_rec *data;
	int pid;

	pid = current->pid;
		
	hash_for_each_possible(tr_hashtable, data, next, pid) {
		if (pid == data->pid) {
			spin_lock(&data->s_lock);
			data->sched++;
			spin_unlock(&data->s_lock);
		}
	}
        return 0; 
}

static int up_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct instr_rec *data;
	int pid;

	pid = current->pid;
	
	hash_for_each_possible(tr_hashtable, data, next, pid) {
		if (pid == data->pid) {
			spin_lock(&data->s_lock);
			data->up++;
			spin_unlock(&data->s_lock);
		}
	}
        return 0; 
}

static int down_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
        struct instr_rec *data;
	int pid;

	pid = current->pid;

	hash_for_each_possible(tr_hashtable, data, next, pid) {
		if (pid == data->pid) {
			spin_lock(&data->s_lock);
			data->down++;
			spin_unlock(&data->s_lock);
		}
	}

        return 0; 
}

static int lock_probe_handler(struct kprobe *p, struct pt_regs *regs)
{	
	struct instr_rec *data;
	int pid;

	pid = current->pid;

	hash_for_each_possible(tr_hashtable, data, next, pid) {
		if (pid == data->pid) {
			spin_lock(&data->s_lock);
			data->lock++;
			spin_unlock(&data->s_lock);
		}
	}
        return 0; 
}

static int unlock_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct instr_rec *data;
	int pid;

	pid = current->pid;


	hash_for_each_possible(tr_hashtable, data, next, pid) {
		if (pid == data->pid) {
			spin_lock(&data->s_lock);
			data->unlock++;
			spin_unlock(&data->s_lock);
		}	
	}
        return 0; 
}

static int exit_probe_handler(struct kprobe *p, struct pt_regs *regs)
{
	struct instr_rec *data;
	struct mem_info *mi_data;
	struct hlist_node *tmp;
	int pid;

	pid = current->pid;

	/* TODO Might not be ok to use kfree here */

	hash_for_each_possible_safe(tr_hashtable, data, tmp, next, pid) {
		if (pid == data->pid) {
			hash_del(&data->next);
			kfree(data);
		}
	}

	hash_for_each_possible_safe(mi_hashtable, mi_data, tmp, next, pid) {
		if (pid == mi_data->pid) {
			hash_del(&mi_data->next);
			kfree(mi_data);
		}
	}
	
	return 0;
}

static struct kretprobe alloc_probe = {
       	.kp.symbol_name = "__kmalloc",
	.entry_handler = alloc_probe_entry_handler,
	.handler = alloc_probe_handler,
	.maxactive = 32,
	.data_size = sizeof(unsigned long),
};

static struct kprobe free_probe = {
	.symbol_name = "kfree",
	.pre_handler = free_probe_handler,
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

static int register_kretprobe_helper(struct kretprobe *krp)
{	
	int ret;

        ret = register_kretprobe(krp);                                
        if (ret < 0) {                                                          
                pr_err("register_kretprobe failed, returned %d\n", ret);        
                return -1;                                                      
        }                                                                       
        pr_info("Planted return probe at %s: %px\n", 
			krp->kp.symbol_name, krp->kp.addr);   

	return 0;
}

static void unregister_kretprobe_helper(struct kretprobe *krp)
{
	unregister_kretprobe(krp);                                    
        pr_info("kretprobe at %p unregistered\n", krp->kp.addr);        
}

static int register_kprobe_helper(struct kprobe *kp)
{
	int ret;

        ret = register_kprobe(kp);                                
        if (ret < 0) {                                                          
                pr_err("register_kprobe failed, returned %d\n", ret);        
                return -1;                                                      
        }                                                                       
        pr_info("Planted probe at %s: %px\n", 
			kp->symbol_name, kp->addr);   

	return 0;
}

static void unregister_kprobe_helper(struct kprobe *kp)
{
	unregister_kprobe(kp);                                    
        pr_info("kprobe at %p unregistered\n", kp->addr);        
}

/*****************************************************************
 * Module init and exit
 */
static int tracer_init(void)
{
	int ret;
	
	proc_tracer = proc_create(PROCFS_FILE, 0000, NULL, &tracer_fops);
	if (!proc_tracer)
		return -ENOMEM;
	
	ret = misc_register(&tracer_dev);
	if (ret)
		return ret;
	pr_info("tracer: got minor %i\n", tracer_dev.minor);

	
#if 0	
#endif
	//register_kretprobe_helper(&alloc_probe);
	//register_kprobe_helper(&free_probe);
	register_kprobe_helper(&exit_probe);
	register_kprobe_helper(&sched_probe);
	register_kprobe_helper(&up_probe);
	register_kprobe_helper(&down_probe);
	register_kprobe_helper(&lock_probe);
	register_kprobe_helper(&unlock_probe);
	
	return 0;
}

static void tracer_exit(void)
{
#if 0	
#endif
	//unregister_kretprobe_helper(&alloc_probe);
	//unregister_kprobe_helper(&free_probe);
	unregister_kprobe_helper(&exit_probe);
	unregister_kprobe_helper(&sched_probe);
	unregister_kprobe_helper(&up_probe);
	unregister_kprobe_helper(&down_probe);
	unregister_kprobe_helper(&lock_probe);
	unregister_kprobe_helper(&unlock_probe);
	
#if 0
#endif
	misc_deregister(&tracer_dev);
	proc_remove(proc_tracer);
	
	delete_hashtable('t');
	delete_hashtable('m');
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Florin Smeu <florin.ion.smeu@gmail.com");
MODULE_LICENSE("GPL v2");
