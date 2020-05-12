#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/cred.h>
#include <linux/fcntl.h>
#include <linux/string.h>

/*
// Files included by /usr/src/linux-headers-4.15.0-45/include/linux/syscalls.h :

#include <linux/types.h>
#include <linux/aio_abi.h>
#include <linux/capability.h>
#include <linux/signal.h>
#include <linux/list.h>
#include <linux/bug.h>
#include <linux/sem.h>
#include <asm/siginfo.h>
#include <linux/unistd.h>
#include <linux/quota.h>
#include <linux/key.h>
#include <trace/syscall.h>
*/

#define PARENTPID 5573
#define STOREORIG(x) org_sys_table[__NR_##x] = sys_call_table[__NR_##x]
#define APPLYCUST(x) sys_call_table[__NR_##x] = (sys_call_ptr_t)custom_##x
#define APPLYORIG(x) sys_call_table[__NR_##x] = org_sys_table[__NR_##x]
#define STOREORIGCONST(x,y) org_sys_table[__NR_##y] = sys_call_table[__NR_##y]
#define APPLYCUSTCONST(x,y) sys_call_table[__NR_##y] = (sys_call_ptr_t)custom_##x
#define APPLYORIGCONST(x,y) sys_call_table[__NR_##y] = org_sys_table[__NR_##y]
#define CUSTFUNC0(x) \
static asmlinkage long custom_##x(void)\
{\
    asmlinkage long (*org_##x)(void);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(void)) org_sys_table[__NR_##x];\
    return org_##x();\
}
#define CUSTFUNC0CONST(x,y) \
static asmlinkage long custom_##x(void)\
{\
    asmlinkage long (*org_##x)(void);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(void)) org_sys_table[__NR_##y];\
    return org_##x();\
}
#define CUSTFUNC1(x,t1,p1) \
static asmlinkage long custom_##x(t1 p1)\
{\
    asmlinkage long (*org_##x)(t1);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(t1)) org_sys_table[__NR_##x];\
    return org_##x(p1);\
}
#define CUSTFUNC1CONST(x,t1,p1,y) \
static asmlinkage long custom_##x(t1 p1)\
{\
    asmlinkage long (*org_##x)(t1);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(t1)) org_sys_table[__NR_##y];\
    return org_##x(p1);\
}
#define CUSTFUNC2(x,t1,p1,t2,p2) \
static asmlinkage long custom_##x(t1 p1, t2 p2)\
{\
    asmlinkage long (*org_##x)(t1, t2);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(t1, t2)) org_sys_table[__NR_##x];\
    return org_##x(p1, p2);\
}
#define CUSTFUNC2CONST(x,t1,p1,t2,p2,y) \
static asmlinkage long custom_##x(t1 p1, t2 p2)\
{\
    asmlinkage long (*org_##x)(t1, t2);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(t1, t2)) org_sys_table[__NR_##y];\
    return org_##x(p1, p2);\
}
#define CUSTFUNC3(x,t1,p1,t2,p2,t3,p3) \
static asmlinkage long custom_##x(t1 p1, t2 p2, t3 p3)\
{\
    asmlinkage long (*org_##x)(t1, t2, t3);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(t1, t2, t3)) org_sys_table[__NR_##x];\
    return org_##x(p1, p2, p3);\
}
#define CUSTFUNC4(x,t1,p1,t2,p2,t3,p3,t4,p4) \
static asmlinkage long custom_##x(t1 p1, t2 p2, t3 p3, t4 p4)\
{\
    asmlinkage long (*org_##x)(t1, t2, t3, t4);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(t1, t2, t3, t4)) org_sys_table[__NR_##x];\
    return org_##x(p1, p2, p3, p4);\
}
#define CUSTFUNC5(x,t1,p1,t2,p2,t3,p3,t4,p4,t5,p5) \
static asmlinkage long custom_##x(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5)\
{\
    asmlinkage long (*org_##x)(t1, t2, t3, t4, t5);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(t1, t2, t3, t4, t5)) org_sys_table[__NR_##x];\
    return org_##x(p1, p2, p3, p4, p5);\
}
#define CUSTFUNC6(x,t1,p1,t2,p2,t3,p3,t4,p4,t5,p5,t6,p6) \
static asmlinkage long custom_##x(t1 p1, t2 p2, t3 p3, t4 p4, t5 p5, t6 p6)\
{\
    asmlinkage long (*org_##x)(t1, t2, t3, t4, t5, t6);\
    if(current->real_parent->pid == PARENTPID)\
    {\
    	printk(KERN_WARNING "ISOLATES:"#x",%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);\
    }\
    org_##x = (asmlinkage long (*)(t1, t2, t3, t4, t5, t6)) org_sys_table[__NR_##x];\
    return org_##x(p1, p2, p3, p4, p5, p6);\
}

MODULE_LICENSE("GPL");

char *sym_name = "sys_call_table";

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
static sys_call_ptr_t *sys_call_table;
static sys_call_ptr_t org_sys_table[2048];

CUSTFUNC1(time, time_t __user *, tloc)
/*
CUSTFUNC1(stime, time_t __user *, tptr)
*/
CUSTFUNC2(gettimeofday, struct timeval __user *, tv,  struct timezone __user *, tz)
CUSTFUNC2(settimeofday, struct timeval __user *, tv,  struct timezone __user *, tz)
CUSTFUNC1(adjtimex, struct timex __user *, txc_p)
CUSTFUNC1(times, struct tms __user *, tbuf)
CUSTFUNC0(gettid)
CUSTFUNC2(nanosleep, struct timespec __user *, rqtp,  struct timespec __user *, rmtp)
CUSTFUNC1(alarm, unsigned int , seconds)
CUSTFUNC0(getpid)
CUSTFUNC0(getppid)
CUSTFUNC0(getuid)
CUSTFUNC0(geteuid)
CUSTFUNC0(getgid)
CUSTFUNC0(getegid)
CUSTFUNC3(getresuid, uid_t __user *, ruid,  uid_t __user *, euid,  uid_t __user *, suid)
CUSTFUNC3(getresgid, gid_t __user *, rgid,  gid_t __user *, egid,  gid_t __user *, sgid)
CUSTFUNC1(getpgid, pid_t , pid)
CUSTFUNC0(getpgrp)
CUSTFUNC1(getsid, pid_t , pid)
CUSTFUNC2(getgroups, int , gidsetsize,  gid_t __user *, grouplist)
CUSTFUNC2(setregid, gid_t , rgid,  gid_t , egid)
CUSTFUNC1(setgid, gid_t , gid)
CUSTFUNC2(setreuid, uid_t , ruid,  uid_t , euid)
CUSTFUNC1(setuid, uid_t , uid)
CUSTFUNC3(setresuid, uid_t , ruid,  uid_t , euid,  uid_t , suid)
CUSTFUNC3(setresgid, gid_t , rgid,  gid_t , egid,  gid_t , sgid)
CUSTFUNC1(setfsuid, uid_t , uid)
CUSTFUNC1(setfsgid, gid_t , gid)
CUSTFUNC2(setpgid, pid_t , pid,  pid_t , pgid)
CUSTFUNC0(setsid)
CUSTFUNC2(setgroups, int , gidsetsize,  gid_t __user *, grouplist)
CUSTFUNC1(acct, const char __user *, name)
CUSTFUNC2(capget, cap_user_header_t , header,  cap_user_data_t , dataptr)
CUSTFUNC2(capset, cap_user_header_t , header,  const cap_user_data_t , data)
CUSTFUNC1(personality, unsigned int , personality)
/*
CUSTFUNC1(sigpending, old_sigset_t __user *, set)
CUSTFUNC3(sigprocmask, int , how,  old_sigset_t __user *, set,  old_sigset_t __user *, oset)
*/
CUSTFUNC2(sigaltstack, const struct sigaltstack __user *, uss,  struct sigaltstack __user *, uoss)
CUSTFUNC2(getitimer, int , which,  struct itimerval __user *, value)
CUSTFUNC3(setitimer, int , which,  struct itimerval __user *, value,  struct itimerval __user *, ovalue)
CUSTFUNC3(timer_create, clockid_t , which_clock,  struct sigevent __user *, timer_event_spec,  timer_t __user * , created_timer_id)
CUSTFUNC2(timer_gettime, timer_t , timer_id,  struct itimerspec __user *, setting)
CUSTFUNC1(timer_getoverrun, timer_t , timer_id)
CUSTFUNC4(timer_settime, timer_t , timer_id,  int , flags,  const struct itimerspec __user *, new_setting,  struct itimerspec __user *, old_setting)
CUSTFUNC1(timer_delete, timer_t , timer_id)
CUSTFUNC2(clock_settime, clockid_t , which_clock,  const struct timespec __user *, tp)
CUSTFUNC2(clock_gettime, clockid_t , which_clock,  struct timespec __user *, tp)
CUSTFUNC2(clock_adjtime, clockid_t , which_clock,  struct timex __user *, tx)
CUSTFUNC2(clock_getres, clockid_t , which_clock,  struct timespec __user *, tp)
CUSTFUNC4(clock_nanosleep, clockid_t , which_clock,  int , flags,  const struct timespec __user *, rqtp,  struct timespec __user *, rmtp)
/*
CUSTFUNC1(nice, int , increment)
*/
CUSTFUNC3(sched_setscheduler, pid_t , pid,  int , policy,  struct sched_param __user *, param)
CUSTFUNC2(sched_setparam, pid_t , pid,  struct sched_param __user *, param)
CUSTFUNC3(sched_setattr, pid_t , pid,  struct sched_attr __user *, attr,  unsigned int , flags)
CUSTFUNC1(sched_getscheduler, pid_t , pid)
CUSTFUNC2(sched_getparam, pid_t , pid,  struct sched_param __user *, param)
CUSTFUNC4(sched_getattr, pid_t , pid,  struct sched_attr __user *, attr,  unsigned int , size,  unsigned int , flags)
CUSTFUNC3(sched_setaffinity, pid_t , pid,  unsigned int , len,  unsigned long __user *, user_mask_ptr)
CUSTFUNC3(sched_getaffinity, pid_t , pid,  unsigned int , len,  unsigned long __user *, user_mask_ptr)
CUSTFUNC0(sched_yield)
CUSTFUNC1(sched_get_priority_max, int , policy)
CUSTFUNC1(sched_get_priority_min, int , policy)
CUSTFUNC2(sched_rr_get_interval, pid_t , pid,  struct timespec __user *, interval)
CUSTFUNC3(setpriority, int , which,  int , who,  int , niceval)
CUSTFUNC2(getpriority, int , which,  int , who)
CUSTFUNC2(shutdown, int , fd,  int , how)
CUSTFUNC4(reboot, int , magic1,  int , magic2,  unsigned int , cmd,  void __user *, arg)
CUSTFUNC0(restart_syscall)
CUSTFUNC4(kexec_load, unsigned long , entry,  unsigned long , nr_segments,  struct kexec_segment __user *, segments,  unsigned long , flags)
CUSTFUNC5(kexec_file_load, int , kernel_fd,  int , initrd_fd,  unsigned long , cmdline_len,  const char __user *, cmdline_ptr,  unsigned long , flags)
CUSTFUNC1(exit, int , error_code)
CUSTFUNC1(exit_group, int , error_code)
CUSTFUNC4(wait4, pid_t , pid,  int __user *, stat_addr,  int , options,  struct rusage __user *, ru)
CUSTFUNC5(waitid, int , which,  pid_t , pid,  struct siginfo __user *, infop,  int , options,  struct rusage __user *, ru)
/*
CUSTFUNC3(waitpid, pid_t , pid,  int __user *, stat_addr,  int , options)
*/
CUSTFUNC1(set_tid_address, int __user *, tidptr)
CUSTFUNC6(futex, u32 __user *, uaddr,  int , op,  u32 , val,  struct timespec __user *, utime,  u32 __user *, uaddr2,  u32 , val3)
CUSTFUNC3(init_module, void __user *, umod,  unsigned long , len,  const char __user *, uargs)
CUSTFUNC2(delete_module, const char __user *, name_user,  unsigned int , flags)
/*
CUSTFUNC1(sigsuspend, old_sigset_t , mask)
CUSTFUNC3(sigsuspend, int , unused1,  int , unused2,  old_sigset_t , mask)
*/
CUSTFUNC2(rt_sigsuspend, sigset_t __user *, unewset,  size_t , sigsetsize)
/*
asmlinkage long sys_sigaction(int, const struct old_sigaction __user *, struct old_sigaction __user *);
*/
CUSTFUNC4(rt_sigaction, int , signum,  const struct sigaction __user *, act,  struct sigaction __user *, oldact,  size_t , sigsetsize)
CUSTFUNC4(rt_sigprocmask, int , how,  sigset_t __user *, set,  sigset_t __user *, oset,  size_t , sigsetsize)
CUSTFUNC2(rt_sigpending, sigset_t __user *, set,  size_t , sigsetsize)
CUSTFUNC4(rt_sigtimedwait, const sigset_t __user *, uthese,  siginfo_t __user *, uinfo,  const struct timespec __user *, uts,  size_t , sigsetsize)
CUSTFUNC4(rt_tgsigqueueinfo, pid_t , tgid,  pid_t  , pid,  int , sig,  siginfo_t __user *, uinfo)
CUSTFUNC2(kill, pid_t , pid,  int , sig)
CUSTFUNC3(tgkill, pid_t , tgid,  pid_t , pid,  int , sig)
CUSTFUNC2(tkill, pid_t , pid,  int , sig)
CUSTFUNC3(rt_sigqueueinfo, pid_t , pid,  int , sig,  siginfo_t __user *, uinfo)
/*
CUSTFUNC0(sgetmask)
CUSTFUNC1(ssetmask, int , newmask)
CUSTFUNC2(signal, int , sig,  __sighandler_t , handler)
*/
CUSTFUNC0(pause)
CUSTFUNC0(sync)
CUSTFUNC1(fsync, unsigned int , fd)
CUSTFUNC1(fdatasync, unsigned int , fd)
/*
CUSTFUNC2(bdflush, int , func,  long , data)
*/
CUSTFUNC5(mount, char __user *, dev_name,  char __user *, dir_name,  char __user *, type,  unsigned long , flags,  void __user *, data)
CUSTFUNC2CONST(umount, char __user *, name,  int , flags, umount2)
/*
#ifdef __NR_umount
CUSTFUNC1(oldumount, char __user *, name)
#endif
*/
CUSTFUNC2(truncate, const char __user *, path,  long , length)
CUSTFUNC2(ftruncate, unsigned int , fd,  unsigned long , length)
CUSTFUNC2(stat, const char __user *, filename,  struct __old_kernel_stat __user *, statbuf)
CUSTFUNC2(statfs, const char __user * , path,  struct statfs __user *, buf)
#ifdef __NR3264_statfs
CUSTFUNC3(statfs64, const char __user *, path,  size_t , sz,  struct statfs64 __user *, buf)
#endif
CUSTFUNC2(fstatfs, unsigned int , fd,  struct statfs __user *, buf)
#ifdef __NR3264_fstatfs
CUSTFUNC3(fstatfs64, unsigned int , fd,  size_t , sz,  struct statfs64 __user *, buf)
#endif
CUSTFUNC2(lstat, const char __user *, filename,  struct __old_kernel_stat __user *, statbuf)
CUSTFUNC2(fstat, unsigned int , fd,  struct __old_kernel_stat __user *, statbuf)
/*
CUSTFUNC2(newstat, const char __user *, filename,  struct stat __user *, statbuf)
CUSTFUNC2(newlstat, const char __user *, filename,  struct stat __user *, statbuf)
CUSTFUNC2(newfstat, unsigned int , fd,  struct stat __user *, statbuf)
*/
CUSTFUNC2(ustat, unsigned , dev,  struct ustat __user *, ubuf)
/*
CUSTFUNC2(stat64, const char __user *, filename,  struct stat64 __user *, statbuf)
CUSTFUNC2(fstat64, unsigned long , fd,  struct stat64 __user *, statbuf)
CUSTFUNC2(lstat64, const char __user *, filename,  struct stat64 __user *, statbuf)
CUSTFUNC4(fstatat64, int , dfd,  const char __user *, filename,  struct stat64 __user *, statbuf,  int , flag)
CUSTFUNC2(truncate64, const char __user *, path,  loff_t , length)
CUSTFUNC2(ftruncate64, unsigned int , fd,  loff_t , length)
*/
CUSTFUNC5(setxattr, const char __user *, path,  const char __user *, name,  const void __user *, value,  size_t , size,  int , flags)
CUSTFUNC5(lsetxattr, const char __user *, path,  const char __user *, name,  const void __user *, value,  size_t , size,  int , flags)
CUSTFUNC5(fsetxattr, int , fd,  const char __user *, name,  const void __user *, value,  size_t , size,  int , flags)
CUSTFUNC4(getxattr, const char __user *, path,  const char __user *, name,  void __user *, value,  size_t , size)
CUSTFUNC4(lgetxattr, const char __user *, path,  const char __user *, name,  void __user *, value,  size_t , size)
CUSTFUNC4(fgetxattr, int , fd,  const char __user *, name,  void __user *, value,  size_t , size)
CUSTFUNC3(listxattr, const char __user *, path,  char __user *, list,  size_t , size)
CUSTFUNC3(llistxattr, const char __user *, path,  char __user *, list,  size_t , size)
CUSTFUNC3(flistxattr, int , fd,  char __user *, list,  size_t , size)
CUSTFUNC2(removexattr, const char __user *, path,  const char __user *, name)
CUSTFUNC2(lremovexattr, const char __user *, path,  const char __user *, name)
CUSTFUNC2(fremovexattr, int , fd,  const char __user *, name)
CUSTFUNC1(brk, unsigned long , brk)
CUSTFUNC3(mprotect, unsigned long , start,  size_t , len,  unsigned long , prot)
CUSTFUNC5(mremap, unsigned long , addr,  unsigned long , old_len,  unsigned long , new_len,  unsigned long , flags,  unsigned long , new_addr)
CUSTFUNC5(remap_file_pages, unsigned long , start,  unsigned long , size,  unsigned long , prot,  unsigned long , pgoff,  unsigned long , flags)
CUSTFUNC3(msync, unsigned long , start,  size_t , len,  int , flags)
CUSTFUNC4(fadvise64, int , fd,  loff_t , offset,  size_t , len,  int , advice)
/*
CUSTFUNC4(fadvise64_64, int , fd,  loff_t , offset,  loff_t , len,  int , advice)
*/
CUSTFUNC2(munmap, unsigned long , addr,  size_t , len)
CUSTFUNC2(mlock, unsigned long , start,  size_t , len)
CUSTFUNC2(munlock, unsigned long , start,  size_t , len)
CUSTFUNC1(mlockall, int , flags)
CUSTFUNC0(munlockall)
CUSTFUNC3(madvise, unsigned long , start,  size_t , len,  int , behavior)
CUSTFUNC3(mincore, unsigned long , start,  size_t , len,  unsigned char __user * , vec)
CUSTFUNC2(pivot_root, const char __user *, new_root,  const char __user *, put_old)
CUSTFUNC1(chroot, const char __user *, filename)
CUSTFUNC3(mknod, const char __user *, filename,  umode_t , mode,  unsigned , dev)
CUSTFUNC2(link, const char __user *, oldname,  const char __user *, newname)
CUSTFUNC2(symlink, const char __user *, old,  const char __user *, new)
CUSTFUNC1(unlink, const char __user *, pathname)
CUSTFUNC2(rename, const char __user *, oldname,  const char __user *, newname)
CUSTFUNC2(chmod, const char __user *, filename,  umode_t , mode)
CUSTFUNC2(fchmod, unsigned int , fd,  umode_t , mode)
CUSTFUNC3(fcntl, unsigned int , fd,  unsigned int , cmd,  unsigned long , arg)
/*
CUSTFUNC3(fcntl64, unsigned int , fd,  unsigned int , cmd,  unsigned long , arg)
*/
CUSTFUNC1(pipe, int __user *, fildes)
CUSTFUNC2(pipe2, int __user *, fildes,  int , flags)
CUSTFUNC1(dup, unsigned int , fildes)
CUSTFUNC2(dup2, unsigned int , oldfd,  unsigned int , newfd)
CUSTFUNC3(dup3, unsigned int , oldfd,  unsigned int , newfd,  int , flags)
CUSTFUNC3(ioperm, unsigned long , from,  unsigned long , num,  int , on)
CUSTFUNC3(ioctl, unsigned int , fd,  unsigned int , cmd,  unsigned long , arg)
CUSTFUNC2(flock, unsigned int , fd,  unsigned int , cmd)
CUSTFUNC2(io_setup, unsigned , nr_reqs,  aio_context_t __user *, ctx)
CUSTFUNC1(io_destroy, aio_context_t , ctx)
CUSTFUNC5(io_getevents, aio_context_t , ctx_id,  long , min_nr,  long , nr,  struct io_event __user *, events,  struct timespec __user *, timeout)
CUSTFUNC3(io_submit, aio_context_t , ctx_id,  long , nr,  struct iocb __user * __user *, uiocbpp)
CUSTFUNC3(io_cancel, aio_context_t , ctx_id,  struct iocb __user *, iocb,  struct io_event __user *, result)
CUSTFUNC4(sendfile, int , out_fd,  int , in_fd,  off_t __user *, offset,  size_t , count)
/*
CUSTFUNC4(sendfile64, int , out_fd,  int , in_fd,  loff_t __user *, offset,  size_t , count)
*/
CUSTFUNC3(readlink, const char __user *, path,  char __user *, buf,  int , bufsiz)
CUSTFUNC2(creat, const char __user *, pathname,  umode_t , mode)
CUSTFUNC3(open, const char __user *, filename,  int , flags,  umode_t , mode)
CUSTFUNC1(close, unsigned int , fd)
CUSTFUNC2(access, const char __user *, filename,  int , mode)
CUSTFUNC0(vhangup)
CUSTFUNC3(chown, const char __user *, filename,  uid_t , user,  gid_t , group)
CUSTFUNC3(lchown, const char __user *, filename,  uid_t , user,  gid_t , group)
CUSTFUNC3(fchown, unsigned int , fd,  uid_t , user,  gid_t , group)
/*
CUSTFUNC3(chown16, const char __user *, filename,  old_uid_t , user,  old_gid_t , group)
CUSTFUNC3(lchown16, const char __user *, filename,  old_uid_t , user,  old_gid_t , group)
CUSTFUNC3(fchown16, unsigned int , fd,  old_uid_t , user,  old_gid_t , group)
CUSTFUNC2(setregid16, old_gid_t , rgid,  old_gid_t , egid)
CUSTFUNC1(setgid16, old_gid_t , gid)
CUSTFUNC2(setreuid16, old_uid_t , ruid,  old_uid_t , euid)
CUSTFUNC1(setuid16, old_uid_t , uid)
CUSTFUNC3(setresuid16, old_uid_t , ruid,  old_uid_t , euid,  old_uid_t , suid)
CUSTFUNC3(getresuid16, old_uid_t __user *, ruid,  old_uid_t __user *, euid,  old_uid_t __user *, suid)
CUSTFUNC3(setresgid16, old_gid_t , rgid,  old_gid_t , egid,  old_gid_t , sgid)
CUSTFUNC3(getresgid16, old_gid_t __user *, rgid,  old_gid_t __user *, egid,  old_gid_t __user *, sgid)
CUSTFUNC1(setfsuid16, old_uid_t , uid)
CUSTFUNC1(setfsgid16, old_gid_t , gid)
CUSTFUNC2(getgroups16, int , gidsetsize,  old_gid_t __user *, grouplist)
CUSTFUNC2(setgroups16, int , gidsetsize,  old_gid_t __user *, grouplist)
CUSTFUNC0(getuid16)
CUSTFUNC0(geteuid16)
CUSTFUNC0(getgid16)
CUSTFUNC0(getegid16)
*/
CUSTFUNC2(utime, char __user *, filename,  struct utimbuf __user *, times)
CUSTFUNC2(utimes, char __user *, filename,  struct timeval __user *, utimes)
CUSTFUNC3(lseek, unsigned int , fd,  off_t , offset,  unsigned int , whence)
/*
CUSTFUNC5(llseek, unsigned int , fd,  unsigned long , offset_high,  unsigned long , offset_low,  loff_t __user *, result,  unsigned int , whence)
*/
CUSTFUNC3(read, unsigned int , fd,  char __user *, buf,  size_t , count)
CUSTFUNC3(readahead, int , fd,  loff_t , offset,  size_t , count)
CUSTFUNC3(readv, unsigned long , fd,  const struct iovec __user *, vec,  unsigned long , vlen)
CUSTFUNC3(write, unsigned int , fd,  const char __user *, buf,  size_t , count)
CUSTFUNC3(writev, unsigned long , fd,  const struct iovec __user *, vec,  unsigned long , vlen)
CUSTFUNC4(pread64, unsigned int , fd,  char __user *, buf,  size_t , count,  loff_t , pos)
CUSTFUNC4(pwrite64, unsigned int , fd,  const char __user *, buf,  size_t , count,  loff_t , pos)
CUSTFUNC5(preadv, unsigned long , fd,  const struct iovec __user *, vec,  unsigned long , vlen,  unsigned long , pos_l,  unsigned long , pos_h)
CUSTFUNC6(preadv2, unsigned long , fd,  const struct iovec __user *, vec,  unsigned long , vlen,  unsigned long , pos_l,  unsigned long , pos_h,  rwf_t , flags)
CUSTFUNC5(pwritev, unsigned long , fd,  const struct iovec __user *, vec,  unsigned long , vlen,  unsigned long , pos_l,  unsigned long , pos_h)
CUSTFUNC6(pwritev2, unsigned long , fd,  const struct iovec __user *, vec,  unsigned long , vlen,  unsigned long , pos_l,  unsigned long , pos_h,  rwf_t , flags)
CUSTFUNC2(getcwd, char __user *, buf,  unsigned long , size)
CUSTFUNC2(mkdir, const char __user *, pathname,  umode_t , mode)
CUSTFUNC1(chdir, const char __user *, filename)
CUSTFUNC1(fchdir, unsigned int , fd)
CUSTFUNC1(rmdir, const char __user *, pathname)
CUSTFUNC3(lookup_dcookie, u64 , cookie64,  char __user *, buf,  size_t , len)
CUSTFUNC4(quotactl, unsigned int , cmd,  const char __user *, special,  qid_t , id,  void __user *, addr)
CUSTFUNC3(getdents, unsigned int , fd,  struct linux_dirent __user *, dirent,  unsigned int , count)
CUSTFUNC3(getdents64, unsigned int , fd,  struct linux_dirent64 __user *, dirent,  unsigned int , count)
CUSTFUNC5(setsockopt, int , fd,  int , level,  int , optname,  char __user *, optval,  int , optlen)
CUSTFUNC5(getsockopt, int , fd,  int , level,  int , optname,  char __user *, optval,  int __user *, optlen)
CUSTFUNC3(bind, int , fd,  struct sockaddr __user *, umyaddr,  int , addrlen)
CUSTFUNC3(connect, int , fd,  struct sockaddr __user *, uservaddr,  int , addrlen)
CUSTFUNC3(accept, int , fd,  struct sockaddr __user *, upeer_sockaddr,  int __user *, upeer_addrlen)
CUSTFUNC4(accept4, int , fd,  struct sockaddr __user *, upeer_sockaddr,  int __user *, upeer_addrlen,  int , flags)
CUSTFUNC3(getsockname, int , fd,  struct sockaddr __user *, usockaddr,  int __user *, usockaddr_len)
CUSTFUNC3(getpeername, int , fd,  struct sockaddr __user *, usockaddr,  int __user *, usockaddr_len)
/*
CUSTFUNC4(send, int , fd,  void __user *, buff,  size_t , len,  unsigned int , flags)
*/
CUSTFUNC6(sendto, int , fd,  void __user *, buff,  size_t , len,  unsigned int , flags,  struct sockaddr __user *, addr,  int , addr_len)
CUSTFUNC3(sendmsg, int , fd,  struct user_msghdr __user *, msg,  unsigned , flags)
CUSTFUNC4(sendmmsg, int , fd,  struct mmsghdr __user *, msg,  unsigned int , vlen,  unsigned , flags)
/*
CUSTFUNC4(recv, int , fd,  void __user *, ubuf,  size_t , size,  unsigned int , flags)
*/
CUSTFUNC6(recvfrom, int , fd,  void __user *, ubuf,  size_t , size,  unsigned int , flags,  struct sockaddr __user *, addr,  int __user *, addr_len)
CUSTFUNC3(recvmsg, int , fd,  struct user_msghdr __user *, msg,  unsigned , flags)
CUSTFUNC5(recvmmsg, int , fd,  struct mmsghdr __user *, msg,  unsigned int , vlen,  unsigned , flags,  struct timespec __user *, timeout)
CUSTFUNC3(socket, int , family,  int , type,  int , protocol)
CUSTFUNC4(socketpair, int , family,  int , type,  int , protocol,  int __user *, usockvec)
/*
CUSTFUNC2(socketcall, int , call,  unsigned long __user *, args)
*/
CUSTFUNC2(listen, int , fd,  int , backlog)
CUSTFUNC3(poll, struct pollfd __user *, ufds,  unsigned int , nfds,  int , timeout)
CUSTFUNC5(select, int , n,  fd_set __user *, inp,  fd_set __user *, outp,  fd_set __user *, exp,  struct timeval __user *, tvp)
/*
CUSTFUNC1(old_select, struct sel_arg_struct __user *, arg)
*/
CUSTFUNC1(epoll_create, int , size)
CUSTFUNC1(epoll_create1, int , flags)
CUSTFUNC4(epoll_ctl, int , epfd,  int , op,  int , fd,  struct epoll_event __user *, event)
CUSTFUNC4(epoll_wait, int , epfd,  struct epoll_event __user *, events,  int , maxevents,  int , timeout)
CUSTFUNC6(epoll_pwait, int , epfd,  struct epoll_event __user *, events,  int , maxevents,  int , timeout,  const sigset_t __user *, sigmask,  size_t , sigsetsize)
/*
CUSTFUNC2(gethostname, char __user *, name,  int , len)
*/
CUSTFUNC2(sethostname, char __user *, name,  int , len)
CUSTFUNC2(setdomainname, char __user *, name,  int , len)
CUSTFUNC1CONST(newuname, struct new_utsname __user *, name, uname)
/*
CUSTFUNC1(uname, struct old_utsname __user *, ubuf)
*/
asmlinkage long sys_olduname(struct oldold_utsname __user *);
CUSTFUNC2(getrlimit, unsigned int , resource,  struct rlimit __user *, rlim)
/*
CUSTFUNC2(old_getrlimit, unsigned int , resource,  struct rlimit __user *, rlim)
*/
CUSTFUNC2(setrlimit, unsigned int , resource,  struct rlimit __user *, rlim)
CUSTFUNC4(prlimit64, pid_t , pid,  unsigned int , resource,  const struct rlimit64 __user *, new_rlim,  struct rlimit64 __user *, old_rlim)
CUSTFUNC2(getrusage, int , who,  struct rusage __user *, ru)
CUSTFUNC1(umask, int , mask)
CUSTFUNC2(msgget, key_t , key,  int , msgflg)
CUSTFUNC4(msgsnd, int , msqid,  struct msgbuf __user *, msgp,  size_t , msgsz,  int , msgflg)
CUSTFUNC5(msgrcv, int , msqid,  struct msgbuf __user *, msgp,  size_t , msgsz,  long , msgtyp,  int , msgflg)
CUSTFUNC3(msgctl, int , msqid,  int , cmd,  struct msqid_ds __user *, buf)
CUSTFUNC3(semget, key_t , key,  int , nsems,  int , semflg)
CUSTFUNC3(semop, int , semid,  struct sembuf __user *, sops,  unsigned , nsops)
CUSTFUNC4(semctl, int , semid,  int , semnum,  int , cmd,  unsigned long , arg)
CUSTFUNC4(semtimedop, int , semid,  struct sembuf __user *, sops,  unsigned , nsops,  const struct timespec __user *, timeout)
CUSTFUNC3(shmat, int , shmid,  char __user *, shmaddr,  int , shmflg)
CUSTFUNC3(shmget, key_t , key,  size_t , size,  int , flag)
CUSTFUNC1(shmdt, char __user *, shmaddr)
CUSTFUNC3(shmctl, int , shmid,  int , cmd,  struct shmid_ds __user *, buf)
/*
CUSTFUNC6(ipc, unsigned int , call,  int , first,  unsigned long , second,  unsigned long , third,  void __user *, ptr,  long , fifth)
*/
CUSTFUNC4(mq_open, const char __user *, name,  int , oflag,  umode_t , mode,  struct mq_attr __user *, attr)
CUSTFUNC1(mq_unlink, const char __user *, name)
CUSTFUNC5(mq_timedsend, mqd_t , mqdes,  const char __user *, msg_ptr,  size_t , msg_len,  unsigned int , msg_prio,  const struct timespec __user *, abs_timeout)
CUSTFUNC5(mq_timedreceive, mqd_t , mqdes,  char __user *, msg_ptr,  size_t , msg_len,  unsigned int __user *, msg_prio,  const struct timespec __user *, abs_timeout)
CUSTFUNC2(mq_notify, mqd_t , mqdes,  const struct sigevent __user *, notification)
CUSTFUNC3(mq_getsetattr, mqd_t , mqdes,  const struct mq_attr __user *, mqstat,  struct mq_attr __user *, omqstat)
/*
CUSTFUNC3(pciconfig_iobase, long , which,  unsigned long , bus,  unsigned long , devfn)
CUSTFUNC5(pciconfig_read, unsigned long , bus,  unsigned long , dfn,  unsigned long , off,  unsigned long , len,  void __user *, buf)
CUSTFUNC5(pciconfig_write, unsigned long , bus,  unsigned long , dfn,  unsigned long , off,  unsigned long , len,  void __user *, buf)
*/
CUSTFUNC5(prctl, int , option,  unsigned long , arg2,  unsigned long , arg3,  unsigned long , arg4,  unsigned long , arg5)
CUSTFUNC2(swapon, const char __user *, specialfile,  int , swap_flags)
CUSTFUNC1(swapoff, const char __user *, specialfile)
/*
CUSTFUNC1(sysctl, struct __sysctl_args __user *, args)
*/
CUSTFUNC1(sysinfo, struct sysinfo __user *, info)
CUSTFUNC3(sysfs, int , option,  unsigned long , arg1,  unsigned long , arg2)
CUSTFUNC3(syslog, int , type,  char __user *, buf,  int , len)
CUSTFUNC1(uselib, const char __user *, library)
CUSTFUNC0CONST(ni_syscall, nfsservctl)
CUSTFUNC4(ptrace, long , request,  long , pid,  unsigned long , addr,  unsigned long , data)
CUSTFUNC5(add_key, const char __user *, _type,  const char __user *, _description,  const void __user *, _payload,  size_t , plen,  key_serial_t , destringid)
CUSTFUNC4(request_key, const char __user *, _type,  const char __user *, _description,  const char __user *, _callout_info,  key_serial_t , destringid)
CUSTFUNC5(keyctl, int , cmd,  unsigned long , arg2,  unsigned long , arg3,  unsigned long , arg4,  unsigned long , arg5)
CUSTFUNC3(ioprio_set, int , which,  int , who,  int , ioprio)
CUSTFUNC2(ioprio_get, int , which,  int , who)
CUSTFUNC3(set_mempolicy, int , mode,  const unsigned long __user *, nmask,  unsigned long , maxnode)
CUSTFUNC4(migrate_pages, pid_t , pid,  unsigned long , maxnode,  const unsigned long __user *, from,  const unsigned long __user *, to)
CUSTFUNC6(move_pages, pid_t , pid,  unsigned long , nr_pages,  const void __user * __user *, pages,  const int __user *, nodes,  int __user *, status,  int , flags)
CUSTFUNC6(mbind, unsigned long , start,  unsigned long , len,  unsigned long , mode,  const unsigned long __user *, nmask,  unsigned long , maxnode,  unsigned , flags)
CUSTFUNC5(get_mempolicy, int __user *, policy,  unsigned long __user *, nmask,  unsigned long , maxnode,  unsigned long , addr,  unsigned long , flags)
CUSTFUNC0(inotify_init)
CUSTFUNC1(inotify_init1, int , flags)
CUSTFUNC3(inotify_add_watch, int , fd,  const char __user *, path,  u32 , mask)
CUSTFUNC2(inotify_rm_watch, int , fd,  __s32 , wd)
/*
CUSTFUNC3(spu_run, int , fd,  __u32 __user *, unpc,  __u32 __user *, ustatus)
CUSTFUNC4(spu_create, const char __user *, name,  unsigned int , flags,  umode_t , mode,  int , fd)
*/
CUSTFUNC4(mknodat, int , dfd,  const char __user * , filename,  umode_t , mode,  unsigned , dev)
CUSTFUNC3(mkdirat, int , dfd,  const char __user * , pathname,  umode_t , mode)
CUSTFUNC3(unlinkat, int , dfd,  const char __user * , pathname,  int , flag)
CUSTFUNC3(symlinkat, const char __user * , oldname,  int , newdfd,  const char __user * , newname)
CUSTFUNC5(linkat, int , olddfd,  const char __user *, oldname,  int , newdfd,  const char __user *, newname,  int , flags)
CUSTFUNC4(renameat, int , olddfd,  const char __user * , oldname,  int , newdfd,  const char __user * , newname)
CUSTFUNC5(renameat2, int , olddfd,  const char __user *, oldname,  int , newdfd,  const char __user *, newname,  unsigned int , flags)
CUSTFUNC3(futimesat, int , dfd,  const char __user *, filename,  struct timeval __user *, utimes)
CUSTFUNC3(faccessat, int , dfd,  const char __user *, filename,  int , mode)
CUSTFUNC3(fchmodat, int , dfd,  const char __user * , filename,  umode_t , mode)
CUSTFUNC5(fchownat, int , dfd,  const char __user *, filename,  uid_t , user,  gid_t , group,  int , flag)
CUSTFUNC4(openat, int , dfd,  const char __user *, filename,  int , flags,  umode_t , mode)
CUSTFUNC4(newfstatat, int , dfd,  const char __user *, filename,  struct stat __user *, statbuf,  int , flag)
CUSTFUNC4(readlinkat, int , dfd,  const char __user *, path,  char __user *, buf,  int , bufsiz)
CUSTFUNC4(utimensat, int , dfd,  const char __user *, filename,  struct timespec __user *, utimes,  int , flags)
CUSTFUNC1(unshare, unsigned long , unshare_flags)
CUSTFUNC6(splice, int , fd_in,  loff_t __user *, off_in,  int , fd_out,  loff_t __user *, off_out,  size_t , len,  unsigned int , flags)
CUSTFUNC4(vmsplice, int , fd,  const struct iovec __user *, iov,  unsigned long , nr_segs,  unsigned int , flags)
CUSTFUNC4(tee, int , fdin,  int , fdout,  size_t , len,  unsigned int , flags)
CUSTFUNC4(sync_file_range, int , fd,  loff_t , offset,  loff_t , nbytes,  unsigned int , flags)
/*
#ifdef __NR_sync_file_range2
CUSTFUNC4(sync_file_range2, int , fd,  unsigned int , flags,  loff_t , offset,  loff_t , nbytes)
#endif
*/
CUSTFUNC3(get_robust_list, int , pid,  struct robust_list_head __user * __user *, head_ptr,  size_t __user *, len_ptr)
CUSTFUNC2(set_robust_list, struct robust_list_head __user *, head,  size_t , len)
CUSTFUNC3(getcpu, unsigned __user *, cpu,  unsigned __user *, node,  struct getcpu_cache __user *, cache)
CUSTFUNC3(signalfd, int , ufd,  sigset_t __user *, user_mask,  size_t , sizemask)
CUSTFUNC4(signalfd4, int , ufd,  sigset_t __user *, user_mask,  size_t , sizemask,  int , flags)
CUSTFUNC2(timerfd_create, int , clockid,  int , flags)
CUSTFUNC4(timerfd_settime, int , ufd,  int , flags,  const struct itimerspec __user *, utmr,  struct itimerspec __user *, otmr)
CUSTFUNC2(timerfd_gettime, int , ufd,  struct itimerspec __user *, otmr)
CUSTFUNC1(eventfd, unsigned int , count)
CUSTFUNC2(eventfd2, unsigned int , count,  int , flags)
CUSTFUNC2(memfd_create, const char __user *, uname_ptr,  unsigned int , flags)
CUSTFUNC1(userfaultfd, int , flags)
CUSTFUNC4(fallocate, int , fd,  int , mode,  loff_t , offset,  loff_t , len)
asmlinkage long sys_old_readdir(unsigned int, struct old_linux_dirent __user *, unsigned int);
CUSTFUNC6(pselect6, int , n,  fd_set __user *, inp,  fd_set __user *, outp,  fd_set __user *, exp,  struct timespec __user *, tsp,  void __user *, sig)
CUSTFUNC5(ppoll, struct pollfd __user *, ufds,  unsigned int , nfds,  struct timespec __user *, tsp,  const sigset_t __user *, sigmask,  size_t , sigsetsize)
CUSTFUNC2(fanotify_init, unsigned int , flags,  unsigned int , event_f_flags)
CUSTFUNC5(fanotify_mark, int , fanotify_fd,  unsigned int , flags,  u64 , mask,  int , fd,  const char  __user *, pathname)
CUSTFUNC1(syncfs, int , fd)
CUSTFUNC0(fork)
CUSTFUNC0(vfork)
/*
asmlinkage long sys_clone(unsigned long, unsigned long, int __user *, unsigned long, int __user *);
asmlinkage long sys_clone(unsigned long, unsigned long, int, int __user *, int __user *, unsigned long);
*/
CUSTFUNC5(clone, unsigned long , clone_flags,  unsigned long , newsp,  int __user *, parent_tid,  int __user *, child_tid,  unsigned long , tls)
CUSTFUNC3(execve, const char __user *, filename,  const char __user *const __user *, argv,  const char __user *const __user *, envp)
CUSTFUNC5(perf_event_open, struct perf_event_attr __user *, attr_uptr,  pid_t , pid,  int , cpu,  int , group_fd,  unsigned long , flags)
/*
CUSTFUNC6(mmap_pgoff, unsigned long , addr,  unsigned long , len,  unsigned long , prot,  unsigned long , flags,  unsigned long , fd,  unsigned long , pgoff)
CUSTFUNC1(old_mmap, struct mmap_arg_struct __user *, arg)
*/
CUSTFUNC5(name_to_handle_at, int , dfd,  const char __user *, name,  struct file_handle __user *, handle,  int __user *, mnt_id,  int , flag)
CUSTFUNC3(open_by_handle_at, int , mountdirfd,  struct file_handle __user *, handle,  int , flags)
CUSTFUNC2(setns, int , fd,  int , nstype)
CUSTFUNC6(process_vm_readv, pid_t , pid,  const struct iovec __user *, lvec,  unsigned long , liovcnt,  const struct iovec __user *, rvec,  unsigned long , riovcnt,  unsigned long , flags)
CUSTFUNC6(process_vm_writev, pid_t , pid,  const struct iovec __user *, lvec,  unsigned long , liovcnt,  const struct iovec __user *, rvec,  unsigned long , riovcnt,  unsigned long , flags)
CUSTFUNC5(kcmp, pid_t , pid1,  pid_t , pid2,  int , type,  unsigned long , idx1,  unsigned long , idx2)
CUSTFUNC3(finit_module, int , fd,  const char __user *, uargs,  int , flags)
CUSTFUNC3(seccomp, unsigned int , op,  unsigned int , flags,  const char __user *, uargs)
CUSTFUNC3(getrandom, char __user *, buf,  size_t , count,  unsigned int , flags)
CUSTFUNC3(bpf, int , cmd,  union bpf_attr *, attr,  unsigned int , size)
CUSTFUNC5(execveat, int , dfd,  const char __user *, filename,  const char __user *const __user *, argv,  const char __user *const __user *, envp,  int , flags)
CUSTFUNC2(membarrier, int , cmd,  int , flags)
CUSTFUNC6(copy_file_range, int , fd_in,  loff_t __user *, off_in,  int , fd_out,  loff_t __user *, off_out,  size_t , len,  unsigned int , flags)
CUSTFUNC3(mlock2, unsigned long , start,  size_t , len,  int , flags)
CUSTFUNC4(pkey_mprotect, unsigned long , start,  size_t , len,  unsigned long , prot,  int , pkey)
CUSTFUNC2(pkey_alloc, unsigned long , flags,  unsigned long , init_val)
CUSTFUNC1(pkey_free, int , pkey)
CUSTFUNC5(statx, int , dfd,  const char __user *, path,  unsigned , flags,  unsigned , mask,  struct statx __user *, buffer)
/*static asmlinkage long custom_open(const char __user *filename, int flags, umode_t mode)*/
/*{*/
/*    asmlinkage long (*old_open)(const char __user *filename, int flags, umode_t mode);*/
/*	char kfilename[256];*/
/*	char *kumode = "DEFAULT";*/
/*	copy_from_user(kfilename, filename, 256);*/
/*    if(current->real_parent->pid == PARENTPID)*/
/*    {*/
/*    	switch(mode)*/
/*    	{*/
/*    		case O_RDONLY : kumode = "O_RDONLY"; break;*/
/*    		case O_WRONLY : kumode ="O_WRONLY"; break;*/
/*    		case O_RDWR : kumode = "O_RDWR"; break;*/
/*    		case O_CREAT : kumode = "O_CREAT"; break;*/
/*//     		case O_EXCL : kumode = "O_EXCL"; break;*/
/*//     		case O_NOCTTY : kumode = "O_NOCTTY"; break;*/
/*    		case O_TRUNC : kumode = "O_TRUNC"; break;*/
/*    		case O_APPEND : kumode = "O_APPEND"; break;*/
/*//     		case O_NDELAY : kumode = "O_NDELAY"; break;*/
/*//     		case O_NONBLOCK : kumode = "O_NONBLOCK"; break;*/
/*//     		case O_SYNC : kumode = "O_SYNC"; break;*/
/*//     		case O_DSYNC : kumode = "O_DSYNC"; break;*/
/*//     		case FASYNC : kumode = "FASYNC"; break;*/
/*//     		case O_DIRECT : kumode = "O_DIRECT"; break;*/
/*//     		case O_LARGEFILE : kumode = "O_LARGEFILE"; break;*/
/*//     		case O_DIRECTORY : kumode = "O_DIRECTORY"; break;*/
/*//     		case O_NOFOLLOW : kumode = "O_NOFOLLOW"; break;*/
/*//     		case O_NOATIME : kumode = "O_NOATIME"; break;*/
/*//     		case O_CLOEXEC : kumode = "O_CLOEXEC"; break;*/
/*//     		case O_PATH : kumode = "O_PATH"; break;*/
/*//     		case O_TMPFILE : kumode = "O_TMPFILE"; break;*/
/*    		*/
/*    	}*/
/*    	printk(KERN_WARNING "ISOLATES:open,%s,%d,%d,%s,%s,%d\n", current->comm, current->pid, current->cred->uid.val, kfilename, kumode, current->real_parent->pid);*/
/*    	return -1;*/
/*    }*/
/*    old_open = (asmlinkage long (*)(const char __user *filename, int flags, umode_t mode)) old_sys_table[__NR_open];*/
/*    return old_open(filename, flags, mode);*/
/*}*/

static int __init hello_init(void)
{
    
    printk(KERN_ALERT "ISOLATES:Custom ReAllOps module inserted successfully\n");
    
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name(sym_name);

// File operations
    
	STOREORIG(open);
/*	  STOREORIG(close);*/
/*	  STOREORIG(read);*/
/*    STOREORIG(write);*/

// Network operations
#ifdef __NR_socketcall	
	STOREORIG(socketcall);
#endif
	STOREORIG(socket);
	STOREORIG(bind);
	STOREORIG(connect);
	STOREORIG(listen);
	STOREORIG(accept);
	STOREORIG(getsockname);
	STOREORIG(getpeername);
	STOREORIG(socketpair);
#ifdef __NR_send
	STOREORIG(send);
#endif
#ifdef __NR_recv
	STOREORIG(recv);
#endif
	STOREORIG(sendto);
	STOREORIG(recvfrom);
	STOREORIG(shutdown);
	STOREORIG(setsockopt);
	STOREORIG(getsockopt);
	STOREORIG(sendmsg);
	STOREORIG(recvmsg);
	STOREORIG(accept4);
	STOREORIG(recvmmsg);
	STOREORIG(sendmmsg);
    
    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));
	
    // Overwrite the syscall table entry
    
// File operations
    
    APPLYCUST(open);
/*    APPLYCUST(close);*/
/*    APPLYCUST(read);*/
/*    APPLYCUST(write);*/

// Network operations
#ifdef __NR_socketcall
	APPLYCUST(socketcall);
#endif
	APPLYCUST(socket);
	APPLYCUST(bind);
	APPLYCUST(connect);
	APPLYCUST(listen);
	APPLYCUST(accept);
	APPLYCUST(getsockname);
	APPLYCUST(getpeername);
	APPLYCUST(socketpair);
#ifdef __NR_send
	APPLYCUST(send);
#endif
#ifdef __NR_recv
	APPLYCUST(recv);
#endif
	APPLYCUST(sendto);
	APPLYCUST(recvfrom);
	APPLYCUST(shutdown);
	APPLYCUST(setsockopt);
	APPLYCUST(getsockopt);
	APPLYCUST(sendmsg);
	APPLYCUST(recvmsg);
	APPLYCUST(accept4);
	APPLYCUST(recvmmsg);
	APPLYCUST(sendmmsg);
       
    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);

    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_ALERT "ISOLATES:Custom ReAllOps module removed successfully\n");
    
    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));

    // Overwrite the syscall table entry

// File operations

    APPLYORIG(open);
/*    APPLYORIG(close);*/
/*    APPLYORIG(read);*/
/*    APPLYORIG(write);  */

// Network operations
#ifdef __NR_socketcall
	APPLYORIG(socketcall);
#endif
	APPLYORIG(socket);
	APPLYORIG(bind);
	APPLYORIG(connect);
	APPLYORIG(listen);
	APPLYORIG(accept);
	APPLYORIG(getsockname);
	APPLYORIG(getpeername);
	APPLYORIG(socketpair);
#ifdef __NR_send
	APPLYORIG(send);
#endif
#ifdef __NR_recv
	APPLYORIG(recv);
#endif
	APPLYORIG(sendto);
	APPLYORIG(recvfrom);
	APPLYORIG(shutdown);
	APPLYORIG(setsockopt);
	APPLYORIG(getsockopt);
	APPLYORIG(sendmsg);
	APPLYORIG(recvmsg);
	APPLYORIG(accept4);
	APPLYORIG(recvmmsg);
	APPLYORIG(sendmmsg);
 
    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);
    
}

module_init(hello_init);
module_exit(hello_exit);

