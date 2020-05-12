#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static struct proc_dir_entry *ent;
static struct file_operations ops;
static long ppid = -1;

static ssize_t ppid_write(struct file *file, const char __user *buf, size_t count, loff_t *pos) 
{
    if(kstrtol_from_user(buf, count, 10, &ppid))
    {
/*    	ppid = -1;*/
    	printk(KERN_WARNING "ppid to be intercepted could not be read\n");
	}
    printk(KERN_WARNING "ppid to be intercepted changed to %ld\n", ppid);
    return count;
}


static int ppid_init(void)
{
    ent = proc_create("ppid", 0666, NULL, &ops);
    if(!ent) return -ENOENT;
    ops.owner = THIS_MODULE;
    ops.write = ppid_write;
    printk(KERN_ALERT "PPID Writer module inserted\n");
    return 0;
}


static void ppid_exit(void)
{
    proc_remove(ent);
    printk(KERN_ALERT "PPID Writer module removed\n");
}


module_init(ppid_init);
module_exit(ppid_exit);

