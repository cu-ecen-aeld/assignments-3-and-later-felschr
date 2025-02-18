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
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Felix Schröter"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

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
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    struct aesd_dev *dev = filp->private_data;
    size_t entry_offset = 0;
    
    if (mutex_lock_interruptible(&dev->lock))
		return -ERESTARTSYS;

    struct aesd_buffer_entry *entry =
        aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_offset);

    if (entry == NULL) {
        mutex_unlock(&dev->lock);
        return retval;
    }

    size_t bytes_to_read = entry->size - entry_offset;
    if (bytes_to_read > count) {
        bytes_to_read = count;
    }

    if (copy_to_user(buf, entry->buffptr + entry_offset, bytes_to_read)) {
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
    ssize_t retval = -ENOMEM;
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle write
     */
    struct aesd_dev *dev = filp->private_data;
    
    if (mutex_lock_interruptible(&dev->lock)) {
        return -ERESTARTSYS;
    }

    if (dev->add_entry.size == 0) {
        dev->add_entry.buffptr = kzalloc(count, GFP_KERNEL);
    } else {
        dev->add_entry.buffptr = krealloc(dev->add_entry.buffptr, dev->add_entry.size + count, GFP_KERNEL);
    }

    if (dev->add_entry.buffptr == 0)
   	{
        mutex_unlock(&dev->lock);
        return retval;
    }

    if (copy_from_user((void *)&dev->add_entry.buffptr[dev->add_entry.size], buf, count))
    {
        mutex_unlock(&dev->lock);
        return -EFAULT;
    }

    dev->add_entry.size += count;

    if (strchr(dev->add_entry.buffptr, '\n') != 0)
    {
        aesd_circular_buffer_add_entry(&dev->buffer, &dev->add_entry);

        dev->add_entry.buffptr = 0;
        dev->add_entry.size = 0;
    }

    mutex_unlock(&dev->lock);
    
    return count;
}
struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
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

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
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
    struct aesd_circular_buffer *buffer = &aesd_device.buffer;
    uint8_t out_offs = buffer->out_offs;
    uint8_t temp_count = 0;
    uint8_t i = 0;

    for (i = out_offs; temp_count < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED; i = (i+1)%AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
    {
        temp_count++;

        if(buffer->entry[i].buffptr != NULL)
        {
            #ifdef __KERNEL__
            kfree(buffer->entry[i].buffptr);
            #else
            free((void*)buffer->entry[i].buffptr);
            #endif
        }
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
