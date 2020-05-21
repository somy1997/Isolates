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
static sys_call_ptr_t old_sys_table[2048];

static asmlinkage long custom_open(const char __user *filename, int flags, umode_t mode)
{
    asmlinkage long (*old_open)(const char __user *filename, int flags, umode_t mode);
    printk(KERN_WARNING "ISOLATES:open,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    old_open = (asmlinkage long (*)(const char __user *filename, int flags, umode_t mode)) old_sys_table[__NR_open];
    return old_open(filename, flags, mode);
}

static asmlinkage long custom_close(unsigned int fd)
{
    asmlinkage long (*old_close)(unsigned int fd);
    printk(KERN_WARNING "ISOLATES:close,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    old_close = (asmlinkage long (*)(unsigned int fd)) old_sys_table[__NR_close];
    return old_close(fd);
}

static asmlinkage long custom_read(unsigned int fd, char __user *buf, size_t count)
{
    asmlinkage long (*old_read)(unsigned int fd, char __user *buf, size_t count);
    printk(KERN_WARNING "ISOLATES:read,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    old_read = (asmlinkage long (*)(unsigned int fd, char __user *buf, size_t count)) old_sys_table[__NR_read];
    return old_read(fd, buf, count);
}

static asmlinkage long custom_write(unsigned int fd, const char __user *buf, size_t count)
{
    asmlinkage long (*old_write)(unsigned int fd, const char __user *buf, size_t count);
    printk(KERN_WARNING "ISOLATES:write,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    old_write = (asmlinkage long (*)(unsigned int fd, const char __user *buf, size_t count)) old_sys_table[__NR_write];
    return old_write(fd, buf, count);
}

static int __init hello_init(void)
{
    
    printk(KERN_ALERT "ISOLATES:Custom FileOps module inserted successfully\n");
    
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name(sym_name);
    
	old_sys_table[__NR_open] = sys_call_table[__NR_open];
	old_sys_table[__NR_close] = sys_call_table[__NR_close];
	old_sys_table[__NR_read] = sys_call_table[__NR_read];
    old_sys_table[__NR_write] = sys_call_table[__NR_write];
    
    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));
	
    // Overwrite the syscall table entry
    sys_call_table[__NR_open] = (sys_call_ptr_t)custom_open;
    sys_call_table[__NR_close] = (sys_call_ptr_t)custom_close;
    sys_call_table[__NR_read] = (sys_call_ptr_t)custom_read;
    sys_call_table[__NR_write] = (sys_call_ptr_t)custom_write;
    
    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);

    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_ALERT "ISOLATES:Custom FileOps module removed successfully\n");
    
    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));

    // Overwrite the syscall table entry
    sys_call_table[__NR_open] = old_sys_table[__NR_open];
    sys_call_table[__NR_close] = old_sys_table[__NR_close];
    sys_call_table[__NR_read] = old_sys_table[__NR_read];
    sys_call_table[__NR_write] = old_sys_table[__NR_write];  
 
    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);
    
}

module_init(hello_init);
module_exit(hello_exit);
