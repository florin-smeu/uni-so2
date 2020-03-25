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

#include "tracer.h"

/*****************************************************************
 * Hashtable info
 */

/*
 * instrumentation record structure
 */
struct instr_rec {
	int pid;

	int alloc;
	int free;
	int alloc_mem;
	int free_mem;
	int sched;
	int up;
	int down;
	int lock;
	int unlock;
	
	struct hlist_node next;
};

DEFINE_HASHTABLE(tr_hashtable, TRACER_HASH_BITS);



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
		seq_printf(m, "%d\t%d\t%d\t\t%d\t\t%d\t%d\t%d\t%d\t%d\t%d\n", 
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

static long tracer_cdev_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	struct instr_rec *data;
	struct instr_rec *crt;
	struct hlist_node *tmp;
	
	pr_info("Device ioctl\n");

	switch (cmd) {
	case TRACER_ADD_PROCESS:
		pr_info("Add process %ld\n", arg);
		data = kmalloc(sizeof(struct instr_rec *), GFP_KERNEL);
		
		data->pid = arg;
		data->alloc = 0;
		data->free = 0;
		data->alloc_mem = 0;
		data->free_mem = 0;
		data->sched = 0;
		data->up = 0;
		data->down = 0;
		data->lock = 0;
		data->unlock = 0;

		hash_add(tr_hashtable, &data->next, data->pid);
		break;
	case TRACER_REMOVE_PROCESS:
		pr_info("Remove process %ld\n", arg);
		
		hash_for_each_possible_safe(tr_hashtable, crt, tmp, next, arg) {
			if (arg == crt->pid) {
				hash_del(&crt->next);
				kfree(crt);
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

static int tracer_init(void)
{
	int retval;
	
	proc_tracer = proc_create(PROCFS_FILE, 0000, NULL, &tracer_fops);
	if (!proc_tracer)
		return -ENOMEM;
	
	retval = misc_register(&tracer_dev);
	if (retval)
		return retval;
	pr_info("tracer: got minor %i\n", tracer_dev.minor);

	return 0;
}

static void tracer_exit(void)
{
	misc_deregister(&tracer_dev);
	proc_remove(proc_tracer);
	/* TODO Free hashmap memory */
}

module_init(tracer_init);
module_exit(tracer_exit);

MODULE_DESCRIPTION("Kprobe based tracer");
MODULE_AUTHOR("Florin Smeu <florin.ion.smeu@gmail.com");
MODULE_LICENSE("GPL v2");
