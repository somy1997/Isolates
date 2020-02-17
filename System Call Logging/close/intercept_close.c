#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/cred.h>


MODULE_LICENSE("GPL");
char *sym_name = "sys_call_table";

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
static sys_call_ptr_t *sys_call_table;
typedef asmlinkage long (*custom_open) (const char __user *filename, int flags, umode_t mode);

custom_open old_open;

static asmlinkage long my_open(const char __user *filename, int flags, umode_t mode)
{
    printk(KERN_WARNING "ISOLATES: open function called by process %s with pid %d by user %d\n", current->comm, current->pid, current->cred->uid.val);
    //pr_WARNING("%s\n",__func__);
    return old_open(filename, flags, mode);
}

static int __init hello_init(void)
{
    
    printk(KERN_ALERT "ISOLATES: Custom Open Module inserted\n");
    
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name(sym_name);
    old_open = (custom_open)sys_call_table[__NR_open];

    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));

    // Overwrite the syscall table entry
    sys_call_table[__NR_open] = (sys_call_ptr_t)my_open;
    
    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);

    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_ALERT "ISOLATES: Custom Open Module removed\n");
    
    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));

    // Overwrite the syscall table entry
    sys_call_table[__NR_open] = (sys_call_ptr_t)old_open;   
 
    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);
    
}

module_init(hello_init);
module_exit(hello_exit);
