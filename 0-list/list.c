// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
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

#define PROCFS_MAX_SIZE		512

#define procfs_dir_name		"list"
#define procfs_file_read	"preview"
#define procfs_file_write	"management"

/*
 * Available list operations
 */
#define ADD_FIRST		"addf"	// Add at the beginning of the list
#define ADD_END			"adde"	// Add at the end of the list
#define DEL_FIRST		"delf"	// Delete first occurrence in list
#define DEL_ALL			"dela"	// Delete all occurrences in list

/*
 * Modes of executing the add or delete operation
 */
#define FIRST			'f'
#define END			'e'
#define ALL			'a'

#define OP_SIZE			5	// Size of an op string (includes '\0')
#define OP_MODE_POS		3	// Position of mode char in op string

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

struct str_list {
	char *str;
	struct list_head list;
};

LIST_HEAD(head);

/*
 * add_str_to_list - Add string entry to list
 *
 * @str: The string to be added
 * @mode: Adding mode (to the front or to the end of the list)
 */
static int add_str_to_list(const char *str, char mode)
{
	size_t size = strlen(str) + 1;
	struct str_list *sle;

	sle = kmalloc(sizeof(*sle), GFP_KERNEL);
	if (!sle)
		return -ENOMEM;

	sle->str = kmalloc(size, GFP_KERNEL);
	if (!sle->str) {
		kfree(sle);
		return -ENOMEM;
	}

	if (strlcpy(sle->str, str, size) >= size)
		return -EPERM;

	switch (mode) {
	case FIRST:
		list_add(&sle->list, &head);
		break;
	case END:
		list_add_tail(&sle->list, &head);
		break;
	default:
		kfree(sle->str);
		kfree(sle);
		return -EPERM;
	}

	return 0;
}

/*
 * del_str_from_list - Delete string entry from list
 *
 * @str: The string to be deleted
 * @mode: Deleting mode (first or all the occurrences of str in the list)
 */
static int del_str_from_list(const char *str, char mode)
{
	struct list_head *i;
	struct list_head *tmp;
	struct str_list *sle;

	switch (mode) {
	case FIRST:
		goto delete_entry;
	case ALL:
		goto delete_entry;
	default:
		return -EPERM;
	}

delete_entry:
	list_for_each_safe(i, tmp, &head) {
		sle = list_entry(i, struct str_list, list);

		if (strcmp(sle->str, str) == 0) {
			list_del(i);
			kfree(sle->str);
			kfree(sle);

			if (mode == FIRST)
				return 0;
		}
	}

	return 0;
}

/*
 * delete_list - Delete memory allocated to store the list
 */
static void delete_list(void)
{
	struct list_head *i;
	struct list_head *tmp;
	struct str_list *sle;

	list_for_each_safe(i, tmp, &head) {
		sle = list_entry(i, struct str_list, list);
		list_del(i);
		kfree(sle->str);
		kfree(sle);
	}
}

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_head *i;
	struct str_list *sle;

	list_for_each(i, &head) {
		sle = list_entry(i, struct str_list, list);
		seq_puts(m, sle->str);
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct  file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char *local_buffer;
	unsigned long local_buffer_size = 0;

	// char that stores the mode of execution for an operation
	// (e.g. FIRST, END, ALL)
	char mode;

	// buffer that stores operation keyword
	// (e.g. ADD_FIRST, ADD_END, DEL_FIRST, DEL_ALL)
	char *op;

	op = kcalloc(OP_SIZE, sizeof(char), GFP_KERNEL);
	if (!op)
		return -ENOMEM;

	local_buffer = kcalloc(PROCFS_MAX_SIZE, sizeof(char), GFP_KERNEL);
	if (!local_buffer)
		return -ENOMEM;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	strlcpy(op, local_buffer, OP_SIZE);

	mode = op[OP_MODE_POS];

	// local buffer will point to the argument of the operation
	if (!strsep(&local_buffer, " "))
		return -EPERM;

	if (strcmp(op, ADD_FIRST) == 0 || strcmp(op, ADD_END) == 0)
		add_str_to_list(local_buffer, mode);
	else if (strcmp(op, DEL_FIRST) == 0 || strcmp(op, DEL_ALL) == 0)
		del_str_from_list(local_buffer, mode);

	return local_buffer_size;
}

static const struct file_operations r_fops = {
	.owner		= THIS_MODULE,
	.open		= list_read_open,
	.read		= seq_read,
	.release	= single_release,
};

static const struct file_operations w_fops = {
	.owner		= THIS_MODULE,
	.open		= list_write_open,
	.write		= list_write,
	.release	= single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read = proc_create(procfs_file_read, 0000, proc_list,
				     &r_fops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write = proc_create(procfs_file_write, 0000, proc_list,
				      &w_fops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	delete_list();
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
MODULE_AUTHOR("Florin Smeu <florin.ion.smeu@gmail.com");
MODULE_LICENSE("GPL v2");
