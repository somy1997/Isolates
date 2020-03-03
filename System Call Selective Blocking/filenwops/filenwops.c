#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/cred.h>
#include <linux/fcntl.h>
#include <linux/string.h>


MODULE_LICENSE("GPL");

char *sym_name = "sys_call_table";

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
static sys_call_ptr_t *sys_call_table;
static sys_call_ptr_t old_sys_table[2048];

// File operations

static asmlinkage long custom_open(const char __user *filename, int flags, umode_t mode)
{
    asmlinkage long (*old_open)(const char __user *filename, int flags, umode_t mode);
	char kfilename[256];
	char *kumode = "DEFAULT";
	copy_from_user(kfilename, filename, 256);
    if(current->real_parent->pid == 12970)
    {
    	switch(mode)
    	{
    		case O_RDONLY : kumode = "O_RDONLY"; break;
    		case O_WRONLY : kumode ="O_WRONLY"; break;
    		case O_RDWR : kumode = "O_RDWR"; break;
    		case O_CREAT : kumode = "O_CREAT"; break;
//     		case O_EXCL : kumode = "O_EXCL"; break;
//     		case O_NOCTTY : kumode = "O_NOCTTY"; break;
    		case O_TRUNC : kumode = "O_TRUNC"; break;
    		case O_APPEND : kumode = "O_APPEND"; break;
//     		case O_NDELAY : kumode = "O_NDELAY"; break;
//     		case O_NONBLOCK : kumode = "O_NONBLOCK"; break;
//     		case O_SYNC : kumode = "O_SYNC"; break;
//     		case O_DSYNC : kumode = "O_DSYNC"; break;
//     		case FASYNC : kumode = "FASYNC"; break;
//     		case O_DIRECT : kumode = "O_DIRECT"; break;
//     		case O_LARGEFILE : kumode = "O_LARGEFILE"; break;
//     		case O_DIRECTORY : kumode = "O_DIRECTORY"; break;
//     		case O_NOFOLLOW : kumode = "O_NOFOLLOW"; break;
//     		case O_NOATIME : kumode = "O_NOATIME"; break;
//     		case O_CLOEXEC : kumode = "O_CLOEXEC"; break;
//     		case O_PATH : kumode = "O_PATH"; break;
//     		case O_TMPFILE : kumode = "O_TMPFILE"; break;
    		
    	}
    	printk(KERN_WARNING "ISOLATES:open,%s,%d,%d,%s,%s,%d\n", current->comm, current->pid, current->cred->uid.val, kfilename, kumode, current->real_parent->pid);
    	return -1;
    }
    old_open = (asmlinkage long (*)(const char __user *filename, int flags, umode_t mode)) old_sys_table[__NR_open];
    return old_open(filename, flags, mode);
}

/*

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

*/

// Network operations
#ifdef __NR_socketcall
static asmlinkage long custom_socketcall(int call, unsigned long __user *args)
{
    asmlinkage long (*old_socketcall)(int call, unsigned long __user *args);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:socketcall,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_socketcall = (asmlinkage long (*)(int call, unsigned long __user *args)) old_sys_table[__NR_socketcall];
    return old_socketcall(call, args);
}
#endif

static asmlinkage long custom_socket(int family, int type, int protocol)
{
    asmlinkage long (*old_socket)(int family, int type, int protocol);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:socket,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_socket = (asmlinkage long (*)(int family, int type, int protocol)) old_sys_table[__NR_socket];
    return old_socket(family, type, protocol);
}

static asmlinkage long custom_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
    asmlinkage long (*old_bind)(int fd, struct sockaddr __user *umyaddr, int addrlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:bind,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_bind = (asmlinkage long (*)(int fd, struct sockaddr __user *umyaddr, int addrlen)) old_sys_table[__NR_bind];
    return old_bind(fd, umyaddr, addrlen);
}

static asmlinkage long custom_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
    asmlinkage long (*old_connect)(int fd, struct sockaddr __user *uservaddr, int addrlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:connect,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_connect = (asmlinkage long (*)(int fd, struct sockaddr __user *uservaddr, int addrlen)) old_sys_table[__NR_connect];
    return old_connect(fd, uservaddr, addrlen);
}

static asmlinkage long custom_listen(int fd, int backlog)
{
    asmlinkage long (*old_listen)(int fd, int backlog);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:listen,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_listen = (asmlinkage long (*)(int fd, int backlog)) old_sys_table[__NR_listen];
    return old_listen(fd, backlog);
}

static asmlinkage long custom_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
    asmlinkage long (*old_accept)(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:accept,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_accept = (asmlinkage long (*)(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)) old_sys_table[__NR_accept];
    return old_accept(fd, upeer_sockaddr, upeer_addrlen);
}

static asmlinkage long custom_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
    asmlinkage long (*old_getsockname)(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getsockname,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_getsockname = (asmlinkage long (*)(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)) old_sys_table[__NR_getsockname];
    return old_getsockname(fd, usockaddr, usockaddr_len);
}

static asmlinkage long custom_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
    asmlinkage long (*old_getpeername)(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getpeername,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_getpeername = (asmlinkage long (*)(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)) old_sys_table[__NR_getpeername];
    return old_getpeername(fd, usockaddr, usockaddr_len);
}

static asmlinkage long custom_socketpair(int family, int type, int protocol, int __user *usockvec)
{
    asmlinkage long (*old_socketpair)(int family, int type, int protocol, int __user *usockvec);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:socketpair,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_socketpair = (asmlinkage long (*)(int family, int type, int protocol, int __user *usockvec)) old_sys_table[__NR_socketpair];
    return old_socketpair(family, type, protocol, usockvec);
}

#ifdef __NR_send
static asmlinkage long custom_send(int fd, void __user *buff, size_t len, unsigned int flags)
{
    asmlinkage long (*old_send)(int fd, void __user *buff, size_t len, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:send,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_send = (asmlinkage long (*)(int fd, void __user *buff, size_t len, unsigned int flags)) old_sys_table[__NR_send];
    return old_send(fd, buff, len, flags);
}
#endif

#ifdef __NR_recv
static asmlinkage long custom_recv(int fd, void __user *ubuf, size_t size, unsigned int flags)
{
    asmlinkage long (*old_recv)(int fd, void __user *ubuf, size_t size, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:recv,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_recv = (asmlinkage long (*)(int fd, void __user *ubuf, size_t size, unsigned int flags)) old_sys_table[__NR_recv];
    return old_recv(fd, ubuf, size, flags);
}
#endif

static asmlinkage long custom_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)
{
    asmlinkage long (*old_sendto)(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sendto,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_sendto = (asmlinkage long (*)(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)) old_sys_table[__NR_sendto];
    return old_sendto(fd, buff, len, flags, addr, addr_len);
}

static asmlinkage long custom_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)
{
    asmlinkage long (*old_recvfrom)(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:recvfrom,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_recvfrom = (asmlinkage long (*)(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)) old_sys_table[__NR_recvfrom];
    return old_recvfrom(fd, ubuf, size, flags, addr, addr_len);
}

static asmlinkage long custom_shutdown(int fd, int how)
{
    asmlinkage long (*old_shutdown)(int fd, int how);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:shutdown,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_shutdown = (asmlinkage long (*)(int fd, int how)) old_sys_table[__NR_shutdown];
    return old_shutdown(fd, how);
}

static asmlinkage long custom_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
{
    asmlinkage long (*old_setsockopt)(int fd, int level, int optname, char __user *optval, int optlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setsockopt,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_setsockopt = (asmlinkage long (*)(int fd, int level, int optname, char __user *optval, int optlen)) old_sys_table[__NR_setsockopt];
    return old_setsockopt(fd, level, optname, optval, optlen);
}

static asmlinkage long custom_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
    asmlinkage long (*old_getsockopt)(int fd, int level, int optname, char __user *optval, int __user *optlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getsockopt,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_getsockopt = (asmlinkage long (*)(int fd, int level, int optname, char __user *optval, int __user *optlen)) old_sys_table[__NR_getsockopt];
    return old_getsockopt(fd, level, optname, optval, optlen);
}

static asmlinkage long custom_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags)
{
    asmlinkage long (*old_sendmsg)(int fd, struct user_msghdr __user *msg, unsigned flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sendmsg,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_sendmsg = (asmlinkage long (*)(int fd, struct user_msghdr __user *msg, unsigned flags)) old_sys_table[__NR_sendmsg];
    return old_sendmsg(fd, msg, flags);
}

static asmlinkage long custom_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags)
{
    asmlinkage long (*old_recvmsg)(int fd, struct user_msghdr __user *msg, unsigned flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:recvmsg,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_recvmsg = (asmlinkage long (*)(int fd, struct user_msghdr __user *msg, unsigned flags)) old_sys_table[__NR_recvmsg];
    return old_recvmsg(fd, msg, flags);
}

#ifdef __NR_accept4
static asmlinkage long custom_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)
{
    asmlinkage long (*old_accept4)(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:accept4,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_accept4 = (asmlinkage long (*)(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)) old_sys_table[__NR_accept4];
    return old_accept4(fd, upeer_sockaddr, upeer_addrlen, flags);
}
#endif

static asmlinkage long custom_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout)
{
    asmlinkage long (*old_recvmmsg)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:recvmmsg,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_recvmmsg = (asmlinkage long (*)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout)) old_sys_table[__NR_recvmmsg];
    return old_recvmmsg(fd, msg, vlen, flags, timeout);
}

static asmlinkage long custom_sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags)
{
    asmlinkage long (*old_sendmmsg)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sendmmsg,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    old_sendmmsg = (asmlinkage long (*)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags)) old_sys_table[__NR_sendmmsg];
    return old_sendmmsg(fd, msg, vlen, flags);
}

static int __init hello_init(void)
{
    
    printk(KERN_ALERT "ISOLATES:Custom FileOps module inserted successfully\n");
    
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name(sym_name);

// File operations
    
	old_sys_table[__NR_open] = sys_call_table[__NR_open];
/*	old_sys_table[__NR_close] = sys_call_table[__NR_close];*/
/*	old_sys_table[__NR_read] = sys_call_table[__NR_read];*/
/*    old_sys_table[__NR_write] = sys_call_table[__NR_write];*/

// Network operations
#ifdef __NR_socketcall	
	old_sys_table[__NR_socketcall] = sys_call_table[__NR_socketcall];
#endif
	old_sys_table[__NR_socket] = sys_call_table[__NR_socket];
	old_sys_table[__NR_bind] = sys_call_table[__NR_bind];
	old_sys_table[__NR_connect] = sys_call_table[__NR_connect];
	old_sys_table[__NR_listen] = sys_call_table[__NR_listen];
	old_sys_table[__NR_accept] = sys_call_table[__NR_accept];
	old_sys_table[__NR_getsockname] = sys_call_table[__NR_getsockname];
	old_sys_table[__NR_getpeername] = sys_call_table[__NR_getpeername];
	old_sys_table[__NR_socketpair] = sys_call_table[__NR_socketpair];
#ifdef __NR_send
	old_sys_table[__NR_send] = sys_call_table[__NR_send];
#endif
#ifdef __NR_recv
	old_sys_table[__NR_recv] = sys_call_table[__NR_recv];
#endif
	old_sys_table[__NR_sendto] = sys_call_table[__NR_sendto];
	old_sys_table[__NR_recvfrom] = sys_call_table[__NR_recvfrom];
	old_sys_table[__NR_shutdown] = sys_call_table[__NR_shutdown];
	old_sys_table[__NR_setsockopt] = sys_call_table[__NR_setsockopt];
	old_sys_table[__NR_getsockopt] = sys_call_table[__NR_getsockopt];
	old_sys_table[__NR_sendmsg] = sys_call_table[__NR_sendmsg];
	old_sys_table[__NR_recvmsg] = sys_call_table[__NR_recvmsg];
	old_sys_table[__NR_accept4] = sys_call_table[__NR_accept4];
	old_sys_table[__NR_recvmmsg] = sys_call_table[__NR_recvmmsg];
	old_sys_table[__NR_sendmmsg] = sys_call_table[__NR_sendmmsg];
    
    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));
	
    // Overwrite the syscall table entry
    
// File operations
    
    sys_call_table[__NR_open] = (sys_call_ptr_t)custom_open;
/*    sys_call_table[__NR_close] = (sys_call_ptr_t)custom_close;*/
/*    sys_call_table[__NR_read] = (sys_call_ptr_t)custom_read;*/
/*    sys_call_table[__NR_write] = (sys_call_ptr_t)custom_write;*/

// Network operations
#ifdef __NR_socketcall
	sys_call_table[__NR_socketcall] = (sys_call_ptr_t)custom_socketcall;
#endif
	sys_call_table[__NR_socket] = (sys_call_ptr_t)custom_socket;
	sys_call_table[__NR_bind] = (sys_call_ptr_t)custom_bind;
	sys_call_table[__NR_connect] = (sys_call_ptr_t)custom_connect;
	sys_call_table[__NR_listen] = (sys_call_ptr_t)custom_listen;
	sys_call_table[__NR_accept] = (sys_call_ptr_t)custom_accept;
	sys_call_table[__NR_getsockname] = (sys_call_ptr_t)custom_getsockname;
	sys_call_table[__NR_getpeername] = (sys_call_ptr_t)custom_getpeername;
	sys_call_table[__NR_socketpair] = (sys_call_ptr_t)custom_socketpair;
#ifdef __NR_send
	sys_call_table[__NR_send] = (sys_call_ptr_t)custom_send;
#endif
#ifdef __NR_recv
	sys_call_table[__NR_recv] = (sys_call_ptr_t)custom_recv;
#endif
	sys_call_table[__NR_sendto] = (sys_call_ptr_t)custom_sendto;
	sys_call_table[__NR_recvfrom] = (sys_call_ptr_t)custom_recvfrom;
	sys_call_table[__NR_shutdown] = (sys_call_ptr_t)custom_shutdown;
	sys_call_table[__NR_setsockopt] = (sys_call_ptr_t)custom_setsockopt;
	sys_call_table[__NR_getsockopt] = (sys_call_ptr_t)custom_getsockopt;
	sys_call_table[__NR_sendmsg] = (sys_call_ptr_t)custom_sendmsg;
	sys_call_table[__NR_recvmsg] = (sys_call_ptr_t)custom_recvmsg;
	sys_call_table[__NR_accept4] = (sys_call_ptr_t)custom_accept4;
	sys_call_table[__NR_recvmmsg] = (sys_call_ptr_t)custom_recvmmsg;
	sys_call_table[__NR_sendmmsg] = (sys_call_ptr_t)custom_sendmmsg;
       
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

// File operations

    sys_call_table[__NR_open] = old_sys_table[__NR_open];
/*    sys_call_table[__NR_close] = old_sys_table[__NR_close];*/
/*    sys_call_table[__NR_read] = old_sys_table[__NR_read];*/
/*    sys_call_table[__NR_write] = old_sys_table[__NR_write];  */

// Network operations
#ifdef __NR_socketcall
	sys_call_table[__NR_socketcall] = old_sys_table[__NR_socketcall];
#endif
	sys_call_table[__NR_socket] = old_sys_table[__NR_socket];
	sys_call_table[__NR_bind] = old_sys_table[__NR_bind];
	sys_call_table[__NR_connect] = old_sys_table[__NR_connect];
	sys_call_table[__NR_listen] = old_sys_table[__NR_listen];
	sys_call_table[__NR_accept] = old_sys_table[__NR_accept];
	sys_call_table[__NR_getsockname] = old_sys_table[__NR_getsockname];
	sys_call_table[__NR_getpeername] = old_sys_table[__NR_getpeername];
	sys_call_table[__NR_socketpair] = old_sys_table[__NR_socketpair];
#ifdef __NR_send
	sys_call_table[__NR_send] = old_sys_table[__NR_send];
#endif
#ifdef __NR_recv
	sys_call_table[__NR_recv] = old_sys_table[__NR_recv];
#endif
	sys_call_table[__NR_sendto] = old_sys_table[__NR_sendto];
	sys_call_table[__NR_recvfrom] = old_sys_table[__NR_recvfrom];
	sys_call_table[__NR_shutdown] = old_sys_table[__NR_shutdown];
	sys_call_table[__NR_setsockopt] = old_sys_table[__NR_setsockopt];
	sys_call_table[__NR_getsockopt] = old_sys_table[__NR_getsockopt];
	sys_call_table[__NR_sendmsg] = old_sys_table[__NR_sendmsg];
	sys_call_table[__NR_recvmsg] = old_sys_table[__NR_recvmsg];
	sys_call_table[__NR_accept4] = old_sys_table[__NR_accept4];
	sys_call_table[__NR_recvmmsg] = old_sys_table[__NR_recvmmsg];
	sys_call_table[__NR_sendmmsg] = old_sys_table[__NR_sendmmsg];
 
    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);
    
}

module_init(hello_init);
module_exit(hello_exit);

