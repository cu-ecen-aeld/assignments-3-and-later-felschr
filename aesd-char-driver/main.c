/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesd-circular-buffer.h"
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Felix Schröter"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

int aesd_open(struct inode *inode, struct file *filp);
int aesd_release(struct inode *inode, struct file *filp);
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos);
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos);
loff_t aesd_llseek(struct file *filp, loff_t offset, int whence);
int aesd_init_module(void);
void aesd_cleanup_module(void);

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    PDEBUG("open");
    /**
     * TODO: handle open
     */
    struct aesd_dev *dev;
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    /**
     * TODO: handle release
     */
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    struct aesd_dev *dev = filp->private_data;
    size_t entry_offset = 0;
    
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    struct aesd_buffer_entry *entry =
        aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_offset);

    if (!entry) {
        mutex_unlock(&dev->lock);
        return 0;
    }

    ssize_t bytes_to_read = entry->size - entry_offset;
    if (bytes_to_read > count) {
        bytes_to_read = count;
    }
    if (copy_to_user(buf, entry->buffptr + entry_offset, bytes_to_read) != 0) {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }
    *f_pos += bytes_to_read;

    mutex_unlock(&dev->lock);

    return bytes_to_read;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    struct aesd_dev *dev = filp->private_data;
    char *new_buf;
    
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    new_buf = kmalloc(dev->add_entry.size + count, GFP_KERNEL);
    if (!new_buf) {
        mutex_unlock(&dev->lock);
        return -ENOMEM;
    }

    if (dev->add_entry.size) {
        memcpy(new_buf, dev->add_entry.buffptr, dev->add_entry.size);
    }
    if (copy_from_user(new_buf + dev->add_entry.size, buf, count) != 0) {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }

    kfree(dev->add_entry.buffptr);
    dev->add_entry.buffptr = new_buf;
    dev->add_entry.size += count;

    while (dev->add_entry.size > 0) {
        char *ptr = memchr(dev->add_entry.buffptr, '\n', dev->add_entry.size);
        struct aesd_buffer_entry entry;
        size_t bytes_written;
        if (!ptr) {
            break;
        }

        bytes_written = ptr + 1 - dev->add_entry.buffptr;
        entry.buffptr = dev->add_entry.buffptr;
        entry.size = bytes_written;
        aesd_circular_buffer_add_entry(&dev->buffer, &entry);

        if (dev->add_entry.size == bytes_written) {
            dev->add_entry.buffptr = NULL;
            dev->add_entry.size = 0;
            break;
        } else {
            new_buf = kmemdup(dev->add_entry.buffptr + bytes_written, dev->add_entry.size - bytes_written, GFP_KERNEL); 
            if (!new_buf) {
                mutex_unlock(&dev->lock);
                return -ENOMEM;
            }
            dev->add_entry.buffptr = new_buf;
            dev->add_entry.size -= bytes_written;
        }
    }
    
    mutex_unlock(&dev->lock);
    return count;
}

loff_t aesd_llseek(struct file *filp, loff_t offset, int whence)
{
    loff_t ret;
    struct aesd_dev *dev = filp->private_data;
    size_t total_length = 0;
    int i;

    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    switch (whence) {
        case SEEK_SET:
            ret = offset;
            break;
        case SEEK_CUR:
            ret = filp->f_pos + offset;
            break;
        case SEEK_END:
            for (i = dev->buffer.out_offs; i != dev->buffer.in_offs; i = (i + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
                total_length += dev->buffer.entry[i].size;
            }
            ret = total_length + offset;
            break;
        default:
            mutex_unlock(&dev->lock);
            return -EINVAL;
    }

    if (ret < 0 || ret > total_length) {
        mutex_unlock(&dev->lock);
        return -EINVAL;
    }

    filp->f_pos = ret;

    mutex_unlock(&dev->lock);

    return ret;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));

    /**
     * TODO: initialize the AESD specific portion of the device
     */
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesd_setup_cdev(&aesd_device);

    if (result) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    /**
     * TODO: cleanup AESD specific poritions here as necessary
     */
    uint8_t i = 0;
    struct aesd_buffer_entry *entry;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, i)
    {
        kfree(entry->buffptr);
    }
    kfree(aesd_device.add_entry.buffptr);

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
