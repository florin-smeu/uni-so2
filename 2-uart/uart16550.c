// SPDX-License-Identifier: GPL-2.0+

/*
 * uart16550.c - UART Driver
 *
 * Author: Florin Smeu <florin.ion.smeu@gmail.com>
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/kfifo.h>

#include "uart16550.h"


static int major = DEFAULT_MAJOR;
static int option = OPTION_BOTH;

module_param(major, int,  0444);
MODULE_PARM_DESC(major, "The major used to register the device");
module_param(option, int,  0444);
MODULE_PARM_DESC(option, "An int that describes device's config options");

struct uart_dev {
	int port;
	struct cdev cdev;

	DECLARE_KFIFO(read_buf, unsigned char, BUFFER_SIZE);
	DECLARE_KFIFO(write_buf, unsigned char, BUFFER_SIZE);

	wait_queue_head_t wq_reads;
	wait_queue_head_t wq_writes;

	spinlock_t lock;
} devs[MAX_MINORS];

/***************************************************************
 * Interrupt handler
 */

irqreturn_t uart_interrupt_handler(int irq_no, void *dev_id)
{
	struct uart_dev *dev;
	unsigned char c;
	unsigned char iir;
	unsigned char ier;
	unsigned char rdai_mask;
	unsigned char threi_mask;
	unsigned int reg;

	dev = (struct uart_dev *)dev_id;

	if (dev->port == UART16550_COM1_SELECTED)
		reg = COM1_REG;
	else if (dev->port == UART16550_COM2_SELECTED)
		reg = COM2_REG;
	else
		return IRQ_NONE;
	
	iir = inb(reg + IIR_OFFSET);
	ier = inb(reg + IER_OFFSET);

	if (iir & INTR_PEND_MASK)
		return IRQ_NONE;
	
	if ((iir & INTR_ID_MASK) == RDAI_ID) {
		c = inb(reg + RBR_OFFSET);
		
		spin_lock(&dev->lock);
		kfifo_in(&dev->read_buf, &c, 1);
		spin_unlock(&dev->lock);
		
		if (kfifo_is_full(&dev->read_buf)) {
			/* Clear RDAI bit in Interrupt Enable Register */
			rdai_mask = RDAI_MASK;
			ier &= (~rdai_mask);
			outb(ier, reg + IER_OFFSET);
		}
	
		wake_up_interruptible(&dev->wq_reads);
	} else if ((iir & INTR_ID_MASK) == THREI_ID) {
		
		while (!kfifo_is_empty(&dev->write_buf)) {
			spin_lock(&dev->lock);
			kfifo_out(&dev->write_buf, &c, 1);
			spin_unlock(&dev->lock);
			outb(c, reg + THR_OFFSET);
		}
		/* Clear THREI bit in Interrupt Enable Register */
		threi_mask = THREI_MASK;
		ier &= (~threi_mask);
		outb(ier, reg + IER_OFFSET);

		wake_up_interruptible(&dev->wq_writes);
	} else {
		return IRQ_NONE;
	}
	
	return IRQ_HANDLED;
}

/***************************************************************
 * Device operations
 */

static int uart_open(struct inode *inode, struct file *file)
{
	struct uart_dev *dev = 
		container_of(inode->i_cdev, struct uart_dev, cdev);
	
	file->private_data = dev;

	pr_info("%s opened\n", MODULE_NAME);
	return 0;
}

static int uart_release(struct inode *inode, struct file *file)
{
	pr_info("%s closed\n", MODULE_NAME);
	return 0;
}

static ssize_t uart_read(struct file *file, char __user *user_buffer,
			 size_t size, loff_t *offset)
{
	int len = 0;
	unsigned int cp;
	int reg;
	unsigned char ier;
	unsigned char rdai_mask;
	unsigned long flags;
	unsigned char tmp[size];
	struct uart_dev *dev = (struct uart_dev *) file->private_data;

	if (kfifo_is_empty(&dev->read_buf)) {
		if (wait_event_interruptible(dev->wq_reads,
					     !kfifo_is_empty(&dev->read_buf)))
			return -ERESTARTSYS;
	}

	pr_info("WAAAIT\n");
	spin_lock_irqsave(&dev->lock, flags);
	
	while (1) {
		if (!kfifo_is_empty(&dev->read_buf)) {
			len = kfifo_len(&dev->read_buf);
			kfifo_out(&dev->read_buf, tmp, len);	
			break;
		}
	}
	
	if (dev->port == UART16550_COM1_SELECTED)
		reg = COM1_REG;
	else if (dev->port == UART16550_COM2_SELECTED)
		reg = COM2_REG;
	else
		return -EFAULT;
	
	/* Set RDAI bit in Interrupt Enable Register */
	ier = inb(reg + IER_OFFSET);
	rdai_mask = RDAI_MASK;
	ier &= (~rdai_mask);
	outb(ier, reg + IER_OFFSET);

	spin_unlock_irqrestore(&dev->lock, flags);
	
	copy_to_user(user_buffer, &tmp, len);
	return len;
}

static ssize_t uart_write(struct file *file, const char __user *user_buffer,
			  size_t size, loff_t *offset)
{
	int i = 0;
	int reg;
	unsigned char ier;
	unsigned char threi_mask;
	unsigned char c;
	unsigned long flags;
	unsigned char tmp[size];

	struct uart_dev *dev = (struct uart_dev *) file->private_data;

	if (file->f_mode & O_NONBLOCK) {
		if (kfifo_avail(&dev->write_buf) == 0)
			return -EAGAIN;
	} else {
		if (wait_event_interruptible(dev->wq_writes, 
				     kfifo_avail(&dev->write_buf) > 0))
		return -ERESTARTSYS;
	}

	// TODO while
	copy_from_user(&tmp, user_buffer, size);

	spin_lock_irqsave(&dev->lock, flags);
	
	while (size) {
		if (!kfifo_is_full(&dev->write_buf)) {
			kfifo_in(&dev->write_buf, &tmp[i], 1);
			i++;
			size--;
		}
	}
	
	if (dev->port == UART16550_COM1_SELECTED)
		reg = COM1_REG;
	else if (dev->port == UART16550_COM2_SELECTED)
		reg = COM2_REG;
	else
		return -EFAULT;

	/* Set THREI bit in Interrupt Enable Register */
	ier = inb(reg + IER_OFFSET);
	threi_mask = THREI_MASK;
	ier &= (~threi_mask);
	outb(ier, reg + IER_OFFSET);
	
	spin_unlock_irqrestore(&dev->lock, flags);
	
	return i;
}

static void set_line_parameters(struct uart16550_line_info *info, int port)
{
	unsigned char params = 0;
	unsigned char set_dlab = 0;
	unsigned char unset_dlab = 0;

	set_dlab |= (1 << 7);
	params |= (info->par | info->len | info->stop);
	
	if (port == UART16550_COM1_SELECTED) {
		/* Handle baud */
		outb(set_dlab, COM1_REG + LCR_OFFSET);
		outb(info->baud, COM1_REG + DLL_OFFSET);
		outb(0, COM1_REG + DLM_OFFSET);
		outb(unset_dlab, COM1_REG + LCR_OFFSET);

		/* Handle all the other parameters */
		outb(params, COM1_REG + LCR_OFFSET);
	} else if (port == UART16550_COM2_SELECTED) {
		/* Handle baud */
		outb(set_dlab, COM2_REG + LCR_OFFSET);
		outb(info->baud, COM2_REG + DLL_OFFSET);
		outb(0, COM2_REG + DLM_OFFSET);
		outb(unset_dlab, COM2_REG + LCR_OFFSET);

		/* Handle all the other parameters */
		outb(params, COM2_REG + LCR_OFFSET);
	}
}

static long uart_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct uart_dev *dev = (struct uart_dev *)file->private_data;
	int err;
	struct uart16550_line_info info;

	switch (cmd) {
	case UART16550_IOCTL_SET_LINE:
		pr_info("IOCTL\n");
		if (copy_from_user(&info, (struct uart16550_line_info *)arg, 
				   sizeof(struct uart16550_line_info))) {
			err = -EINVAL;
			goto ioctl_err;
		}

		set_line_parameters(&info, dev->port);

		break;     		
	default:
		err = -EINVAL;
		goto ioctl_err;
	}
	return 0;
ioctl_err:
	return err;
}

static const struct file_operations uart_fops = {
	.owner		= THIS_MODULE,
	.open		= uart_open,
	.release	= uart_release,
	.read		= uart_read,
	.write		= uart_write,
	.unlocked_ioctl = uart_ioctl
};

/***************************************************************
 * Module init and exit functions 
 */

static int init_helper(int minor, int dev_idx, int reg, int irq)
{
	int err;

	err = register_chrdev_region(MKDEV(major, minor), 1, MODULE_NAME);
	if (err) {
		pr_err("register_region failed: %d\n", err);
		goto out;
	}

	if (request_region(reg, REG_SIZE, MODULE_NAME) == NULL) {
		err = -EBUSY;
		pr_err("request_region failed: %d\n", err);
		goto out_unregister;
	}
	
	err = request_irq(irq, uart_interrupt_handler, IRQF_SHARED,
			  MODULE_NAME, &devs[dev_idx]);
	if (err) {
		pr_err("request_irq failed: %d\n", err);
		goto out_release_region;
	}
	
	/* Activate all interrupts */
	outb(INTR_EN_MASK, reg + MCR_OFFSET);
	/* Activate RDAI and THREI */
	outb(RDAI_MASK | THREI_MASK, reg + IER_OFFSET);

	if (dev_idx == COM1_IDX)
		devs[dev_idx].port = UART16550_COM1_SELECTED;
	else if (dev_idx == COM2_IDX)
		devs[dev_idx].port = UART16550_COM2_SELECTED;

	INIT_KFIFO(devs[dev_idx].write_buf);
	INIT_KFIFO(devs[dev_idx].read_buf);

	spin_lock_init(&devs[dev_idx].lock);

	init_waitqueue_head(&devs[dev_idx].wq_reads);
	init_waitqueue_head(&devs[dev_idx].wq_writes);

	cdev_init(&devs[dev_idx].cdev, &uart_fops);
        cdev_add(&devs[dev_idx].cdev, MKDEV(major, minor), 1);

	return 0;

out_release_region:
	release_region(reg, REG_SIZE);

out_unregister:
	unregister_chrdev_region(MKDEV(major, minor), 1);

out:
	return err;
}

static int __init uart_init(void)
{
	int err;

	switch (option) {
	case OPTION_COM1:
		err = init_helper(COM1_MINOR, COM1_IDX, COM1_REG, IRQ_COM1);
		if (err)
			goto out;
		break;
	case OPTION_COM2:
		err = init_helper(COM2_MINOR, COM2_IDX, COM2_REG, IRQ_COM2);
		if (err)
			goto out;
		break;
	default:
		err = init_helper(COM1_MINOR, COM1_IDX, COM1_REG, IRQ_COM1);
		if (err)
			goto out;
		
		err = init_helper(COM2_MINOR, COM2_IDX, COM2_REG, IRQ_COM2);
		if (err)
			goto out;
	}

	pr_notice("Driver %s loaded\n", MODULE_NAME);
	return 0;

out:
	return err;
}

static void exit_helper(int minor, int dev_idx, int reg, int irq)
{
	cdev_del(&devs[dev_idx].cdev);
	free_irq(irq, &devs[dev_idx]);
	release_region(reg, REG_SIZE);
	unregister_chrdev_region(MKDEV(major, minor), 1);
}

static void __exit uart_exit(void)
{
	switch (option) {
	case OPTION_COM1:
		exit_helper(COM1_MINOR, COM1_IDX, COM1_REG, IRQ_COM1);
		break;
	case OPTION_COM2:
		exit_helper(COM2_MINOR, COM2_IDX, COM2_REG, IRQ_COM2);
		break;
	default:
		exit_helper(COM1_MINOR, COM1_IDX, COM1_REG, IRQ_COM1);
		exit_helper(COM2_MINOR, COM2_IDX, COM2_REG, IRQ_COM2);
	}

	pr_notice("Driver %s unloaded\n", MODULE_NAME);
}

module_init(uart_init);
module_exit(uart_exit);

MODULE_DESCRIPTION("UART Driver");
MODULE_AUTHOR("Florin Smeu <florin.ion.smeu@gmail.com");
MODULE_LICENSE("GPL v2");
