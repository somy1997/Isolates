#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>

        
MODULE_LICENSE ("GPL");
        
unsigned long *sys_call_table;
        
asmlinkage long (*original_sys_unlink) (const char *pathname);

/*return -1. this will prevent any process from unlinking any file*/
asmlinkage long hacked_sys_unlink(const char *pathname)
{
        return -1;
}
        
static int __init my_init (void)
{
	printk(KERN_ALERT "Entered my_init\n");
        /*obtain sys_call_table from hardcoded value
        we found in System.map*/
        sys_call_table=0xffffffff81e001e0;
        sys_call_table=0x81e001e0;
        
	printk(KERN_ALERT "Assigned address to sys_call_table, calling xchg now\n");
        /*store original location of sys_unlink. Alter sys_call_table
        to point _ _NR_unlink to our hacked_sys_unlink*/
        original_sys_unlink =(void * )xchg(&sys_call_table[__NR_unlink],
hacked_sys_unlink);
        printk(KERN_ALERT "xchg called successfully, original sys unlink swapped with hacked sys unlink\n");
        return 0;
}

static void my_exit (void)
{
/*restore original sys_unlink in sys_call_table*/
	printk(KERN_ALERT "Entered my_exit\n");
        xchg(&sys_call_table[__NR_unlink], original_sys_unlink);
	printk(KERN_ALERT "xchg called successfully, original sys unlink restored\n");
}       

module_init(my_init);
module_exit(my_exit);

