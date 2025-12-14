/*
 * sysinfo_plus.c
 * Advanced example kernel module that logs snapshots and exposes interfaces:
 *  - /proc/sysinfo_plus (seq file)
 *  - /sys/kernel/sysinfo_plus/{log_level,interval,last_snapshot,logs_count}
 *  - /dev/sysinfo_plus (character device): read -> JSON snapshot
 *  - ioctl to trigger immediate snapshot
 *
 * Build: make
 * Author: Ahmed Nour Allah
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/utsname.h>
#include <linux/sysinfo.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/timekeeping.h>
#include <linux/sched/loadavg.h>
#include <linux/mm.h>
#include <linux/version.h>

#define DRIVER_NAME "sysinfo_plus"
#define PROC_NAME "sysinfo_plus"
#define DEV_NAME "sysinfo_plus"
#define CLASS_NAME "sysinfo_plus_class"
#define IOCTL_TRIGGER _IO('s', 1)

static unsigned int interval_sec = 5;
module_param(interval_sec, uint, 0644);
MODULE_PARM_DESC(interval_sec, "Snapshot interval in seconds");

static int log_level = 1;
module_param(log_level, int, 0644);
MODULE_PARM_DESC(log_level, "Logging level (0=none,1=info)");

struct snapshot {
    u64 ts;
    unsigned long totalram_kb;
    unsigned long freeram_kb;
    unsigned int cpu_count;
    unsigned long uptime_sec;
    unsigned long loads[3];
};

static struct snapshot latest_snapshot;
static unsigned long logs_count;
static struct mutex snap_lock;
static struct timer_list snap_timer;
static struct proc_dir_entry *proc_entry;
static struct kobject *sys_kobj;
static dev_t dev_number;
static struct cdev sys_cdev;
static struct class *sys_class;

static void collect_snapshot(struct snapshot *s)
{
    struct sysinfo si;

    si_meminfo(&si);
    get_avenrun(si.loads, 0, SI_LOAD_SHIFT);

    s->ts = (u64)ktime_get_seconds();
    s->totalram_kb = (si.totalram * si.mem_unit) >> 10;
    s->freeram_kb = (si.freeram * si.mem_unit) >> 10;
    s->cpu_count = num_online_cpus();
    s->uptime_sec = (unsigned long)si.uptime;
    s->loads[0] = si.loads[0];
    s->loads[1] = si.loads[1];
    s->loads[2] = si.loads[2];
}

static void snap_timer_fn(struct timer_list *t)
{
    mutex_lock(&snap_lock);
    collect_snapshot(&latest_snapshot);
    logs_count++;
    if (log_level)
        printk(KERN_INFO DRIVER_NAME ": snapshot %lu: uptime=%lu s, totalram=%lu KB, freeram=%lu KB\n",
               logs_count, latest_snapshot.uptime_sec, latest_snapshot.totalram_kb, latest_snapshot.freeram_kb);
    mutex_unlock(&snap_lock);

    mod_timer(&snap_timer, jiffies + msecs_to_jiffies(interval_sec * 1000));
}

static void trigger_snapshot(void)
{
    mutex_lock(&snap_lock);
    collect_snapshot(&latest_snapshot);
    logs_count++;
    if (log_level)
        printk(KERN_INFO DRIVER_NAME ": manual snapshot triggered\n");
    mutex_unlock(&snap_lock);
}

static int proc_show(struct seq_file *m, void *v)
{
    mutex_lock(&snap_lock);
    seq_printf(m,
               "Snapshot time (s since boot): %llu\n"
               "Kernel version: %s\n"
               "Total RAM: %lu KB\n"
               "Free RAM: %lu KB\n"
               "CPU count: %u\n"
               "Uptime (s): %lu\n"
               "Loads (fixed point): %lu %lu %lu\n"
               "Snapshots taken: %lu\n",
               latest_snapshot.ts,
               utsname()->release,
               latest_snapshot.totalram_kb,
               latest_snapshot.freeram_kb,
               latest_snapshot.cpu_count,
               latest_snapshot.uptime_sec,
               latest_snapshot.loads[0], latest_snapshot.loads[1], latest_snapshot.loads[2],
               logs_count);
    mutex_unlock(&snap_lock);
    return 0;
}

static int proc_open_fn(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops proc_fops = {
    .proc_open = proc_open_fn,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};
#else
static const struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .open = proc_open_fn,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
};
#endif

static ssize_t log_level_show(struct kobject *k, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%d\n", log_level);
}

static ssize_t log_level_store(struct kobject *k, struct kobj_attribute *attr, const char *buf, size_t count)
{
    int val;

    if (kstrtoint(buf, 10, &val) < 0)
        return -EINVAL;

    log_level = val;
    return count;
}

static struct kobj_attribute log_level_attr = __ATTR(log_level, 0664, log_level_show, log_level_store);

static ssize_t interval_show(struct kobject *k, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%u\n", interval_sec);
}

static ssize_t interval_store(struct kobject *k, struct kobj_attribute *attr, const char *buf, size_t count)
{
    unsigned int val;

    if (kstrtouint(buf, 10, &val) < 0)
        return -EINVAL;

    if (val == 0)
        return -EINVAL;

    interval_sec = val;
    mod_timer(&snap_timer, jiffies + msecs_to_jiffies(interval_sec * 1000));
    return count;
}

static struct kobj_attribute interval_attr = __ATTR(interval, 0664, interval_show, interval_store);

static ssize_t last_snapshot_show(struct kobject *k, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%llu\n", latest_snapshot.ts);
}

static struct kobj_attribute last_snapshot_attr = __ATTR_RO(last_snapshot);

static ssize_t logs_count_show(struct kobject *k, struct kobj_attribute *attr, char *buf)
{
    return sprintf(buf, "%lu\n", logs_count);
}

static struct kobj_attribute logs_count_attr = __ATTR_RO(logs_count);

static struct attribute *sysinfo_attrs[] = {
    &log_level_attr.attr,
    &interval_attr.attr,
    &last_snapshot_attr.attr,
    &logs_count_attr.attr,
    NULL,
};

static struct attribute_group attr_group = {
    .attrs = sysinfo_attrs,
};

static ssize_t dev_read(struct file *file, char __user *buf, size_t len, loff_t *ppos)
{
    char *kbuf;
    int printed;
    ssize_t ret;

    kbuf = kzalloc(512, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    mutex_lock(&snap_lock);
    printed = scnprintf(kbuf, 512,
                        "{ \"ts\": %llu, \"kernel\": \"%s\", \"totalram_kb\": %lu, \"freeram_kb\": %lu, \"cpu_count\": %u, \"uptime_sec\": %lu, \"loads\": [%lu,%lu,%lu], \"logs_count\": %lu }\n",
                        latest_snapshot.ts,
                        utsname()->release,
                        latest_snapshot.totalram_kb,
                        latest_snapshot.freeram_kb,
                        latest_snapshot.cpu_count,
                        latest_snapshot.uptime_sec,
                        latest_snapshot.loads[0], latest_snapshot.loads[1], latest_snapshot.loads[2],
                        logs_count);
    mutex_unlock(&snap_lock);

    if (*ppos >= printed) {
        ret = 0;
        goto out;
    }

    if (len > printed - *ppos)
        len = printed - *ppos;

    if (copy_to_user(buf, kbuf + *ppos, len)) {
        ret = -EFAULT;
        goto out;
    }

    *ppos += len;
    ret = len;

out:
    kfree(kbuf);
    return ret;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    if (_IOC_TYPE(cmd) != _IOC_TYPE(IOCTL_TRIGGER))
        return -ENOTTY;

    if (cmd == IOCTL_TRIGGER) {
        trigger_snapshot();
        return 0;
    }

    return -ENOTTY;
}

static const struct file_operations dev_fops = {
    .owner = THIS_MODULE,
    .read = dev_read,
    .unlocked_ioctl = dev_ioctl,
};

static int __init sysinfo_plus_init(void)
{
    int ret;

    mutex_init(&snap_lock);
    collect_snapshot(&latest_snapshot);
    logs_count = 1;

    proc_entry = proc_create(PROC_NAME, 0444, NULL, &proc_fops);
    if (!proc_entry) {
        printk(KERN_ERR DRIVER_NAME ": proc_create failed\n");
        ret = -ENOMEM;
        goto err;
    }

    sys_kobj = kobject_create_and_add(DRIVER_NAME, kernel_kobj);
    if (!sys_kobj) {
        printk(KERN_ERR DRIVER_NAME ": kobject_create failed\n");
        ret = -ENOMEM;
        goto err_proc;
    }

    ret = sysfs_create_group(sys_kobj, &attr_group);
    if (ret) {
        printk(KERN_ERR DRIVER_NAME ": sysfs_create_group failed\n");
        goto err_kobj;
    }

    ret = alloc_chrdev_region(&dev_number, 0, 1, DEV_NAME);
    if (ret < 0) {
        printk(KERN_ERR DRIVER_NAME ": alloc_chrdev_region failed\n");
        goto err_sysfs;
    }

    cdev_init(&sys_cdev, &dev_fops);
    sys_cdev.owner = THIS_MODULE;
    ret = cdev_add(&sys_cdev, dev_number, 1);
    if (ret) {
        printk(KERN_ERR DRIVER_NAME ": cdev_add failed\n");
        goto err_chrdev;
    }

    /* class_create signature changed in newer kernels (drops module arg). */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
    sys_class = class_create(CLASS_NAME);
#else
    sys_class = class_create(THIS_MODULE, CLASS_NAME);
#endif
    if (IS_ERR(sys_class)) {
        ret = PTR_ERR(sys_class);
        printk(KERN_ERR DRIVER_NAME ": class_create failed\n");
        goto err_cdev_add;
    }

    if (IS_ERR(device_create(sys_class, NULL, dev_number, NULL, DEV_NAME))) {
        ret = -ENOMEM;
        printk(KERN_ERR DRIVER_NAME ": device_create failed\n");
        goto err_class;
    }

    timer_setup(&snap_timer, snap_timer_fn, 0);
    mod_timer(&snap_timer, jiffies + msecs_to_jiffies(interval_sec * 1000));

    printk(KERN_INFO DRIVER_NAME ": initialized\n");
    return 0;

err_class:
    class_destroy(sys_class);
err_cdev_add:
    cdev_del(&sys_cdev);
err_chrdev:
    unregister_chrdev_region(dev_number, 1);
err_sysfs:
    sysfs_remove_group(sys_kobj, &attr_group);
err_kobj:
    kobject_put(sys_kobj);
err_proc:
    proc_remove(proc_entry);
err:
    return ret;
}

static void __exit sysinfo_plus_exit(void)
{
    del_timer_sync(&snap_timer);
    device_destroy(sys_class, dev_number);
    class_destroy(sys_class);
    cdev_del(&sys_cdev);
    unregister_chrdev_region(dev_number, 1);
    sysfs_remove_group(sys_kobj, &attr_group);
    kobject_put(sys_kobj);
    proc_remove(proc_entry);
    printk(KERN_INFO DRIVER_NAME ": exited\n");
}

module_init(sysinfo_plus_init);
module_exit(sysinfo_plus_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ahmed Nour Allah");
MODULE_DESCRIPTION("Advanced sysinfo kernel module with proc/sysfs/char device and timer snapshots");
