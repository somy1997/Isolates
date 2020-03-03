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

MODULE_LICENSE("GPL");

char *sym_name = "sys_call_table";

typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
static sys_call_ptr_t *sys_call_table;
static sys_call_ptr_t org_sys_table[2048];

#ifdef __NR_time
static asmlinkage long custom_time(time_t __user *tloc)
{
    asmlinkage long (*org_time)(time_t __user *tloc);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:time,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_time = (asmlinkage long (*)(time_t __user *tloc)) org_sys_table[__NR_time];
    return org_time(tloc);
}
#endif

#ifdef __NR_stime
static asmlinkage long custom_stime(time_t __user *tptr)
{
    asmlinkage long (*org_stime)(time_t __user *tptr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:stime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_stime = (asmlinkage long (*)(time_t __user *tptr)) org_sys_table[__NR_stime];
    return org_stime(tptr);
}
#endif

#ifdef __NR_gettimeofday
static asmlinkage long custom_gettimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
    asmlinkage long (*org_gettimeofday)(struct timeval __user *tv, struct timezone __user *tz);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:gettimeofday,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_gettimeofday = (asmlinkage long (*)(struct timeval __user *tv, struct timezone __user *tz)) org_sys_table[__NR_gettimeofday];
    return org_gettimeofday(tv, tz);
}
#endif

#ifdef __NR_settimeofday
static asmlinkage long custom_settimeofday(struct timeval __user *tv, struct timezone __user *tz)
{
    asmlinkage long (*org_settimeofday)(struct timeval __user *tv, struct timezone __user *tz);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:settimeofday,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_settimeofday = (asmlinkage long (*)(struct timeval __user *tv, struct timezone __user *tz)) org_sys_table[__NR_settimeofday];
    return org_settimeofday(tv, tz);
}
#endif

#ifdef __NR_adjtimex
static asmlinkage long custom_adjtimex(struct timex __user *txc_p)
{
    asmlinkage long (*org_adjtimex)(struct timex __user *txc_p);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:adjtimex,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_adjtimex = (asmlinkage long (*)(struct timex __user *txc_p)) org_sys_table[__NR_adjtimex];
    return org_adjtimex(txc_p);
}
#endif


#ifdef __NR_times
static asmlinkage long custom_times(struct tms __user *tbuf)
{
    asmlinkage long (*org_times)(struct tms __user *tbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:times,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_times = (asmlinkage long (*)(struct tms __user *tbuf)) org_sys_table[__NR_times];
    return org_times(tbuf);
}
#endif


#ifdef __NR_gettid
static asmlinkage long custom_gettid(void)
{
    asmlinkage long (*org_gettid)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:gettid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_gettid = (asmlinkage long (*)(void)) org_sys_table[__NR_gettid];
    return org_gettid();
}
#endif

#ifdef __NR_nanosleep
static asmlinkage long custom_nanosleep(struct timespec __user *rqtp, struct timespec __user *rmtp)
{
    asmlinkage long (*org_nanosleep)(struct timespec __user *rqtp, struct timespec __user *rmtp);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:nanosleep,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_nanosleep = (asmlinkage long (*)(struct timespec __user *rqtp, struct timespec __user *rmtp)) org_sys_table[__NR_nanosleep];
    return org_nanosleep(rqtp, rmtp);
}
#endif

#ifdef __NR_alarm
static asmlinkage long custom_alarm(unsigned int seconds)
{
    asmlinkage long (*org_alarm)(unsigned int seconds);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:alarm,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_alarm = (asmlinkage long (*)(unsigned int seconds)) org_sys_table[__NR_alarm];
    return org_alarm(seconds);
}
#endif

#ifdef __NR_getpid
static asmlinkage long custom_getpid(void)
{
    asmlinkage long (*org_getpid)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getpid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getpid = (asmlinkage long (*)(void)) org_sys_table[__NR_getpid];
    return org_getpid();
}
#endif

#ifdef __NR_getppid
static asmlinkage long custom_getppid(void)
{
    asmlinkage long (*org_getppid)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getppid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getppid = (asmlinkage long (*)(void)) org_sys_table[__NR_getppid];
    return org_getppid();
}
#endif

#ifdef __NR_getuid
static asmlinkage long custom_getuid(void)
{
    asmlinkage long (*org_getuid)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getuid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getuid = (asmlinkage long (*)(void)) org_sys_table[__NR_getuid];
    return org_getuid();
}
#endif

#ifdef __NR_geteuid
static asmlinkage long custom_geteuid(void)
{
    asmlinkage long (*org_geteuid)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:geteuid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_geteuid = (asmlinkage long (*)(void)) org_sys_table[__NR_geteuid];
    return org_geteuid();
}
#endif

#ifdef __NR_getgid
static asmlinkage long custom_getgid(void)
{
    asmlinkage long (*org_getgid)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getgid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getgid = (asmlinkage long (*)(void)) org_sys_table[__NR_getgid];
    return org_getgid();
}
#endif

#ifdef __NR_getegid
static asmlinkage long custom_getegid(void)
{
    asmlinkage long (*org_getegid)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getegid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getegid = (asmlinkage long (*)(void)) org_sys_table[__NR_getegid];
    return org_getegid();
}
#endif

#ifdef __NR_getresuid
static asmlinkage long custom_getresuid(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)
{
    asmlinkage long (*org_getresuid)(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getresuid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getresuid = (asmlinkage long (*)(uid_t __user *ruid, uid_t __user *euid, uid_t __user *suid)) org_sys_table[__NR_getresuid];
    return org_getresuid(ruid, euid, suid);
}
#endif

#ifdef __NR_getresgid
static asmlinkage long custom_getresgid(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)
{
    asmlinkage long (*org_getresgid)(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getresgid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getresgid = (asmlinkage long (*)(gid_t __user *rgid, gid_t __user *egid, gid_t __user *sgid)) org_sys_table[__NR_getresgid];
    return org_getresgid(rgid, egid, sgid);
}
#endif

#ifdef __NR_getpgid
static asmlinkage long custom_getpgid(pid_t pid)
{
    asmlinkage long (*org_getpgid)(pid_t pid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getpgid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getpgid = (asmlinkage long (*)(pid_t pid)) org_sys_table[__NR_getpgid];
    return org_getpgid(pid);
}
#endif

#ifdef __NR_getpgrp
static asmlinkage long custom_getpgrp(void)
{
    asmlinkage long (*org_getpgrp)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getpgrp,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getpgrp = (asmlinkage long (*)(void)) org_sys_table[__NR_getpgrp];
    return org_getpgrp();
}
#endif

#ifdef __NR_getsid
static asmlinkage long custom_getsid(pid_t pid)
{
    asmlinkage long (*org_getsid)(pid_t pid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getsid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getsid = (asmlinkage long (*)(pid_t pid)) org_sys_table[__NR_getsid];
    return org_getsid(pid);
}
#endif

#ifdef __NR_getgroups
static asmlinkage long custom_getgroups(int gidsetsize, gid_t __user *grouplist)
{
    asmlinkage long (*org_getgroups)(int gidsetsize, gid_t __user *grouplist);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getgroups,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getgroups = (asmlinkage long (*)(int gidsetsize, gid_t __user *grouplist)) org_sys_table[__NR_getgroups];
    return org_getgroups(gidsetsize, grouplist);
}
#endif


#ifdef __NR_setregid
static asmlinkage long custom_setregid(gid_t rgid, gid_t egid)
{
    asmlinkage long (*org_setregid)(gid_t rgid, gid_t egid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setregid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setregid = (asmlinkage long (*)(gid_t rgid, gid_t egid)) org_sys_table[__NR_setregid];
    return org_setregid(rgid, egid);
}
#endif

#ifdef __NR_setgid
static asmlinkage long custom_setgid(gid_t gid)
{
    asmlinkage long (*org_setgid)(gid_t gid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setgid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setgid = (asmlinkage long (*)(gid_t gid)) org_sys_table[__NR_setgid];
    return org_setgid(gid);
}
#endif

#ifdef __NR_setreuid
static asmlinkage long custom_setreuid(uid_t ruid, uid_t euid)
{
    asmlinkage long (*org_setreuid)(uid_t ruid, uid_t euid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setreuid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setreuid = (asmlinkage long (*)(uid_t ruid, uid_t euid)) org_sys_table[__NR_setreuid];
    return org_setreuid(ruid, euid);
}
#endif

#ifdef __NR_setuid
static asmlinkage long custom_setuid(uid_t uid)
{
    asmlinkage long (*org_setuid)(uid_t uid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setuid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setuid = (asmlinkage long (*)(uid_t uid)) org_sys_table[__NR_setuid];
    return org_setuid(uid);
}
#endif

#ifdef __NR_setresuid
static asmlinkage long custom_setresuid(uid_t ruid, uid_t euid, uid_t suid)
{
    asmlinkage long (*org_setresuid)(uid_t ruid, uid_t euid, uid_t suid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setresuid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setresuid = (asmlinkage long (*)(uid_t ruid, uid_t euid, uid_t suid)) org_sys_table[__NR_setresuid];
    return org_setresuid(ruid, euid, suid);
}
#endif

#ifdef __NR_setresgid
static asmlinkage long custom_setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    asmlinkage long (*org_setresgid)(gid_t rgid, gid_t egid, gid_t sgid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setresgid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setresgid = (asmlinkage long (*)(gid_t rgid, gid_t egid, gid_t sgid)) org_sys_table[__NR_setresgid];
    return org_setresgid(rgid, egid, sgid);
}
#endif

#ifdef __NR_setfsuid
static asmlinkage long custom_setfsuid(uid_t uid)
{
    asmlinkage long (*org_setfsuid)(uid_t uid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setfsuid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setfsuid = (asmlinkage long (*)(uid_t uid)) org_sys_table[__NR_setfsuid];
    return org_setfsuid(uid);
}
#endif

#ifdef __NR_setfsgid
static asmlinkage long custom_setfsgid(gid_t gid)
{
    asmlinkage long (*org_setfsgid)(gid_t gid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setfsgid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setfsgid = (asmlinkage long (*)(gid_t gid)) org_sys_table[__NR_setfsgid];
    return org_setfsgid(gid);
}
#endif

#ifdef __NR_setpgid
static asmlinkage long custom_setpgid(pid_t pid, pid_t pgid)
{
    asmlinkage long (*org_setpgid)(pid_t pid, pid_t pgid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setpgid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setpgid = (asmlinkage long (*)(pid_t pid, pid_t pgid)) org_sys_table[__NR_setpgid];
    return org_setpgid(pid, pgid);
}
#endif

#ifdef __NR_setsid
static asmlinkage long custom_setsid(void)
{
    asmlinkage long (*org_setsid)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setsid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setsid = (asmlinkage long (*)(void)) org_sys_table[__NR_setsid];
    return org_setsid();
}
#endif

#ifdef __NR_setgroups
static asmlinkage long custom_setgroups(int gidsetsize, gid_t __user *grouplist)
{
    asmlinkage long (*org_setgroups)(int gidsetsize, gid_t __user *grouplist);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setgroups,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setgroups = (asmlinkage long (*)(int gidsetsize, gid_t __user *grouplist)) org_sys_table[__NR_setgroups];
    return org_setgroups(gidsetsize, grouplist);
}
#endif


#ifdef __NR_acct
static asmlinkage long custom_acct(const char __user *name)
{
    asmlinkage long (*org_acct)(const char __user *name);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:acct,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_acct = (asmlinkage long (*)(const char __user *name)) org_sys_table[__NR_acct];
    return org_acct(name);
}
#endif

#ifdef __NR_capget
static asmlinkage long custom_capget(cap_user_header_t header, cap_user_data_t dataptr)
{
    asmlinkage long (*org_capget)(cap_user_header_t header, cap_user_data_t dataptr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:capget,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_capget = (asmlinkage long (*)(cap_user_header_t header, cap_user_data_t dataptr)) org_sys_table[__NR_capget];
    return org_capget(header, dataptr);
}
#endif

#ifdef __NR_capset
static asmlinkage long custom_capset(cap_user_header_t header, const cap_user_data_t data)
{
    asmlinkage long (*org_capset)(cap_user_header_t header, const cap_user_data_t data);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:capset,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_capset = (asmlinkage long (*)(cap_user_header_t header, const cap_user_data_t data)) org_sys_table[__NR_capset];
    return org_capset(header, data);
}
#endif

#ifdef __NR_personality
static asmlinkage long custom_personality(unsigned int personality)
{
    asmlinkage long (*org_personality)(unsigned int personality);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:personality,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_personality = (asmlinkage long (*)(unsigned int personality)) org_sys_table[__NR_personality];
    return org_personality(personality);
}
#endif


#ifdef __NR_sigpending
static asmlinkage long custom_sigpending(old_sigset_t __user *set)
{
    asmlinkage long (*org_sigpending)(old_sigset_t __user *set);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sigpending,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sigpending = (asmlinkage long (*)(old_sigset_t __user *set)) org_sys_table[__NR_sigpending];
    return org_sigpending(set);
}
#endif

#ifdef __NR_sigprocmask
static asmlinkage long custom_sigprocmask(int how, old_sigset_t __user *set, old_sigset_t __user *oset)
{
    asmlinkage long (*org_sigprocmask)(int how, old_sigset_t __user *set, old_sigset_t __user *oset);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sigprocmask,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sigprocmask = (asmlinkage long (*)(int how, old_sigset_t __user *set, old_sigset_t __user *oset)) org_sys_table[__NR_sigprocmask];
    return org_sigprocmask(how, set, oset);
}
#endif

#ifdef __NR_sigaltstack
static asmlinkage long custom_sigaltstack(const struct sigaltstack __user *uss, struct sigaltstack __user *uoss)
{
    asmlinkage long (*org_sigaltstack)(const struct sigaltstack __user *uss, struct sigaltstack __user *uoss);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sigaltstack,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sigaltstack = (asmlinkage long (*)(const struct sigaltstack __user *uss, struct sigaltstack __user *uoss)) org_sys_table[__NR_sigaltstack];
    return org_sigaltstack(uss, uoss);
}
#endif


#ifdef __NR_getitimer
static asmlinkage long custom_getitimer(int which, struct itimerval __user *value)
{
    asmlinkage long (*org_getitimer)(int which, struct itimerval __user *value);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getitimer,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getitimer = (asmlinkage long (*)(int which, struct itimerval __user *value)) org_sys_table[__NR_getitimer];
    return org_getitimer(which, value);
}
#endif

#ifdef __NR_setitimer
static asmlinkage long custom_setitimer(int which, struct itimerval __user *value, struct itimerval __user *ovalue)
{
    asmlinkage long (*org_setitimer)(int which, struct itimerval __user *value, struct itimerval __user *ovalue);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setitimer,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setitimer = (asmlinkage long (*)(int which, struct itimerval __user *value, struct itimerval __user *ovalue)) org_sys_table[__NR_setitimer];
    return org_setitimer(which, value, ovalue);
}
#endif

#ifdef __NR_timer_create
static asmlinkage long custom_timer_create(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id)
{
    asmlinkage long (*org_timer_create)(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:timer_create,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_timer_create = (asmlinkage long (*)(clockid_t which_clock, struct sigevent __user *timer_event_spec, timer_t __user * created_timer_id)) org_sys_table[__NR_timer_create];
    return org_timer_create(which_clock, timer_event_spec, created_timer_id);
}
#endif

#ifdef __NR_timer_gettime
static asmlinkage long custom_timer_gettime(timer_t timer_id, struct itimerspec __user *setting)
{
    asmlinkage long (*org_timer_gettime)(timer_t timer_id, struct itimerspec __user *setting);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:timer_gettime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_timer_gettime = (asmlinkage long (*)(timer_t timer_id, struct itimerspec __user *setting)) org_sys_table[__NR_timer_gettime];
    return org_timer_gettime(timer_id, setting);
}
#endif

#ifdef __NR_timer_getoverrun
static asmlinkage long custom_timer_getoverrun(timer_t timer_id)
{
    asmlinkage long (*org_timer_getoverrun)(timer_t timer_id);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:timer_getoverrun,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_timer_getoverrun = (asmlinkage long (*)(timer_t timer_id)) org_sys_table[__NR_timer_getoverrun];
    return org_timer_getoverrun(timer_id);
}
#endif

#ifdef __NR_timer_settime
static asmlinkage long custom_timer_settime(timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting)
{
    asmlinkage long (*org_timer_settime)(timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:timer_settime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_timer_settime = (asmlinkage long (*)(timer_t timer_id, int flags, const struct itimerspec __user *new_setting, struct itimerspec __user *old_setting)) org_sys_table[__NR_timer_settime];
    return org_timer_settime(timer_id, flags, new_setting, old_setting);
}
#endif

#ifdef __NR_timer_delete
static asmlinkage long custom_timer_delete(timer_t timer_id)
{
    asmlinkage long (*org_timer_delete)(timer_t timer_id);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:timer_delete,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_timer_delete = (asmlinkage long (*)(timer_t timer_id)) org_sys_table[__NR_timer_delete];
    return org_timer_delete(timer_id);
}
#endif

#ifdef __NR_clock_settime
static asmlinkage long custom_clock_settime(clockid_t which_clock, const struct timespec __user *tp)
{
    asmlinkage long (*org_clock_settime)(clockid_t which_clock, const struct timespec __user *tp);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:clock_settime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_clock_settime = (asmlinkage long (*)(clockid_t which_clock, const struct timespec __user *tp)) org_sys_table[__NR_clock_settime];
    return org_clock_settime(which_clock, tp);
}
#endif

#ifdef __NR_clock_gettime
static asmlinkage long custom_clock_gettime(clockid_t which_clock, struct timespec __user *tp)
{
    asmlinkage long (*org_clock_gettime)(clockid_t which_clock, struct timespec __user *tp);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:clock_gettime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_clock_gettime = (asmlinkage long (*)(clockid_t which_clock, struct timespec __user *tp)) org_sys_table[__NR_clock_gettime];
    return org_clock_gettime(which_clock, tp);
}
#endif

#ifdef __NR_clock_adjtime
static asmlinkage long custom_clock_adjtime(clockid_t which_clock, struct timex __user *tx)
{
    asmlinkage long (*org_clock_adjtime)(clockid_t which_clock, struct timex __user *tx);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:clock_adjtime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_clock_adjtime = (asmlinkage long (*)(clockid_t which_clock, struct timex __user *tx)) org_sys_table[__NR_clock_adjtime];
    return org_clock_adjtime(which_clock, tx);
}
#endif

#ifdef __NR_clock_getres
static asmlinkage long custom_clock_getres(clockid_t which_clock, struct timespec __user *tp)
{
    asmlinkage long (*org_clock_getres)(clockid_t which_clock, struct timespec __user *tp);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:clock_getres,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_clock_getres = (asmlinkage long (*)(clockid_t which_clock, struct timespec __user *tp)) org_sys_table[__NR_clock_getres];
    return org_clock_getres(which_clock, tp);
}
#endif

#ifdef __NR_clock_nanosleep
static asmlinkage long custom_clock_nanosleep(clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp)
{
    asmlinkage long (*org_clock_nanosleep)(clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:clock_nanosleep,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_clock_nanosleep = (asmlinkage long (*)(clockid_t which_clock, int flags, const struct timespec __user *rqtp, struct timespec __user *rmtp)) org_sys_table[__NR_clock_nanosleep];
    return org_clock_nanosleep(which_clock, flags, rqtp, rmtp);
}
#endif


#ifdef __NR_nice
static asmlinkage long custom_nice(int increment)
{
    asmlinkage long (*org_nice)(int increment);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:nice,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_nice = (asmlinkage long (*)(int increment)) org_sys_table[__NR_nice];
    return org_nice(increment);
}
#endif

#ifdef __NR_sched_setscheduler
static asmlinkage long custom_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
{
    asmlinkage long (*org_sched_setscheduler)(pid_t pid, int policy, struct sched_param __user *param);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_setscheduler,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_setscheduler = (asmlinkage long (*)(pid_t pid, int policy, struct sched_param __user *param)) org_sys_table[__NR_sched_setscheduler];
    return org_sched_setscheduler(pid, policy, param);
}
#endif

#ifdef __NR_sched_setparam
static asmlinkage long custom_sched_setparam(pid_t pid, struct sched_param __user *param)
{
    asmlinkage long (*org_sched_setparam)(pid_t pid, struct sched_param __user *param);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_setparam,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_setparam = (asmlinkage long (*)(pid_t pid, struct sched_param __user *param)) org_sys_table[__NR_sched_setparam];
    return org_sched_setparam(pid, param);
}
#endif

#ifdef __NR_sched_setattr
static asmlinkage long custom_sched_setattr(pid_t pid, struct sched_attr __user *attr, unsigned int flags)
{
    asmlinkage long (*org_sched_setattr)(pid_t pid, struct sched_attr __user *attr, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_setattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_setattr = (asmlinkage long (*)(pid_t pid, struct sched_attr __user *attr, unsigned int flags)) org_sys_table[__NR_sched_setattr];
    return org_sched_setattr(pid, attr, flags);
}
#endif

#ifdef __NR_sched_getscheduler
static asmlinkage long custom_sched_getscheduler(pid_t pid)
{
    asmlinkage long (*org_sched_getscheduler)(pid_t pid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_getscheduler,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_getscheduler = (asmlinkage long (*)(pid_t pid)) org_sys_table[__NR_sched_getscheduler];
    return org_sched_getscheduler(pid);
}
#endif

#ifdef __NR_sched_getparam
static asmlinkage long custom_sched_getparam(pid_t pid, struct sched_param __user *param)
{
    asmlinkage long (*org_sched_getparam)(pid_t pid, struct sched_param __user *param);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_getparam,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_getparam = (asmlinkage long (*)(pid_t pid, struct sched_param __user *param)) org_sys_table[__NR_sched_getparam];
    return org_sched_getparam(pid, param);
}
#endif

#ifdef __NR_sched_getattr
static asmlinkage long custom_sched_getattr(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags)
{
    asmlinkage long (*org_sched_getattr)(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_getattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_getattr = (asmlinkage long (*)(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags)) org_sys_table[__NR_sched_getattr];
    return org_sched_getattr(pid, attr, size, flags);
}
#endif

#ifdef __NR_sched_setaffinity
static asmlinkage long custom_sched_setaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
    asmlinkage long (*org_sched_setaffinity)(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_setaffinity,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_setaffinity = (asmlinkage long (*)(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)) org_sys_table[__NR_sched_setaffinity];
    return org_sched_setaffinity(pid, len, user_mask_ptr);
}
#endif

#ifdef __NR_sched_getaffinity
static asmlinkage long custom_sched_getaffinity(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)
{
    asmlinkage long (*org_sched_getaffinity)(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_getaffinity,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_getaffinity = (asmlinkage long (*)(pid_t pid, unsigned int len, unsigned long __user *user_mask_ptr)) org_sys_table[__NR_sched_getaffinity];
    return org_sched_getaffinity(pid, len, user_mask_ptr);
}
#endif

#ifdef __NR_sched_yield
static asmlinkage long custom_sched_yield(void)
{
    asmlinkage long (*org_sched_yield)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_yield,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_yield = (asmlinkage long (*)(void)) org_sys_table[__NR_sched_yield];
    return org_sched_yield();
}
#endif

#ifdef __NR_sched_get_priority_max
static asmlinkage long custom_sched_get_priority_max(int policy)
{
    asmlinkage long (*org_sched_get_priority_max)(int policy);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_get_priority_max,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_get_priority_max = (asmlinkage long (*)(int policy)) org_sys_table[__NR_sched_get_priority_max];
    return org_sched_get_priority_max(policy);
}
#endif

#ifdef __NR_sched_get_priority_min
static asmlinkage long custom_sched_get_priority_min(int policy)
{
    asmlinkage long (*org_sched_get_priority_min)(int policy);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_get_priority_min,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_get_priority_min = (asmlinkage long (*)(int policy)) org_sys_table[__NR_sched_get_priority_min];
    return org_sched_get_priority_min(policy);
}
#endif

#ifdef __NR_sched_rr_get_interval
static asmlinkage long custom_sched_rr_get_interval(pid_t pid, struct timespec __user *interval)
{
    asmlinkage long (*org_sched_rr_get_interval)(pid_t pid, struct timespec __user *interval);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sched_rr_get_interval,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sched_rr_get_interval = (asmlinkage long (*)(pid_t pid, struct timespec __user *interval)) org_sys_table[__NR_sched_rr_get_interval];
    return org_sched_rr_get_interval(pid, interval);
}
#endif

#ifdef __NR_setpriority
static asmlinkage long custom_setpriority(int which, int who, int niceval)
{
    asmlinkage long (*org_setpriority)(int which, int who, int niceval);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setpriority,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setpriority = (asmlinkage long (*)(int which, int who, int niceval)) org_sys_table[__NR_setpriority];
    return org_setpriority(which, who, niceval);
}
#endif

#ifdef __NR_getpriority
static asmlinkage long custom_getpriority(int which, int who)
{
    asmlinkage long (*org_getpriority)(int which, int who);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getpriority,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getpriority = (asmlinkage long (*)(int which, int who)) org_sys_table[__NR_getpriority];
    return org_getpriority(which, who);
}
#endif


#ifdef __NR_shutdown
static asmlinkage long custom_shutdown(int fd, int how)
{
    asmlinkage long (*org_shutdown)(int fd, int how);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:shutdown,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_shutdown = (asmlinkage long (*)(int fd, int how)) org_sys_table[__NR_shutdown];
    return org_shutdown(fd, how);
}
#endif

#ifdef __NR_reboot
static asmlinkage long custom_reboot(int magic1, int magic2, unsigned int cmd, void __user *arg)
{
    asmlinkage long (*org_reboot)(int magic1, int magic2, unsigned int cmd, void __user *arg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:reboot,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_reboot = (asmlinkage long (*)(int magic1, int magic2, unsigned int cmd, void __user *arg)) org_sys_table[__NR_reboot];
    return org_reboot(magic1, magic2, cmd, arg);
}
#endif

#ifdef __NR_restart_syscall
static asmlinkage long custom_restart_syscall(void)
{
    asmlinkage long (*org_restart_syscall)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:restart_syscall,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_restart_syscall = (asmlinkage long (*)(void)) org_sys_table[__NR_restart_syscall];
    return org_restart_syscall();
}
#endif

#ifdef __NR_kexec_load
static asmlinkage long custom_kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags)
{
    asmlinkage long (*org_kexec_load)(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:kexec_load,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_kexec_load = (asmlinkage long (*)(unsigned long entry, unsigned long nr_segments, struct kexec_segment __user *segments, unsigned long flags)) org_sys_table[__NR_kexec_load];
    return org_kexec_load(entry, nr_segments, segments, flags);
}
#endif

#ifdef __NR_kexec_file_load
static asmlinkage long custom_kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags)
{
    asmlinkage long (*org_kexec_file_load)(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:kexec_file_load,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_kexec_file_load = (asmlinkage long (*)(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags)) org_sys_table[__NR_kexec_file_load];
    return org_kexec_file_load(kernel_fd, initrd_fd, cmdline_len, cmdline_ptr, flags);
}
#endif


#ifdef __NR_exit
static asmlinkage long custom_exit(int error_code)
{
    asmlinkage long (*org_exit)(int error_code);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:exit,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_exit = (asmlinkage long (*)(int error_code)) org_sys_table[__NR_exit];
    return org_exit(error_code);
}
#endif

#ifdef __NR_exit_group
static asmlinkage long custom_exit_group(int error_code)
{
    asmlinkage long (*org_exit_group)(int error_code);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:exit_group,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_exit_group = (asmlinkage long (*)(int error_code)) org_sys_table[__NR_exit_group];
    return org_exit_group(error_code);
}
#endif

#ifdef __NR_wait4
static asmlinkage long custom_wait4(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru)
{
    asmlinkage long (*org_wait4)(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:wait4,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_wait4 = (asmlinkage long (*)(pid_t pid, int __user *stat_addr, int options, struct rusage __user *ru)) org_sys_table[__NR_wait4];
    return org_wait4(pid, stat_addr, options, ru);
}
#endif

#ifdef __NR_waitid
static asmlinkage long custom_waitid(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru)
{
    asmlinkage long (*org_waitid)(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:waitid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_waitid = (asmlinkage long (*)(int which, pid_t pid, struct siginfo __user *infop, int options, struct rusage __user *ru)) org_sys_table[__NR_waitid];
    return org_waitid(which, pid, infop, options, ru);
}
#endif

#ifdef __NR_waitpid
static asmlinkage long custom_waitpid(pid_t pid, int __user *stat_addr, int options)
{
    asmlinkage long (*org_waitpid)(pid_t pid, int __user *stat_addr, int options);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:waitpid,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_waitpid = (asmlinkage long (*)(pid_t pid, int __user *stat_addr, int options)) org_sys_table[__NR_waitpid];
    return org_waitpid(pid, stat_addr, options);
}
#endif

#ifdef __NR_set_tid_address
static asmlinkage long custom_set_tid_address(int __user *tidptr)
{
    asmlinkage long (*org_set_tid_address)(int __user *tidptr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:set_tid_address,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_set_tid_address = (asmlinkage long (*)(int __user *tidptr)) org_sys_table[__NR_set_tid_address];
    return org_set_tid_address(tidptr);
}
#endif

#ifdef __NR_futex
static asmlinkage long custom_futex(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)
{
    asmlinkage long (*org_futex)(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:futex,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_futex = (asmlinkage long (*)(u32 __user *uaddr, int op, u32 val, struct timespec __user *utime, u32 __user *uaddr2, u32 val3)) org_sys_table[__NR_futex];
    return org_futex(uaddr, op, val, utime, uaddr2, val3);
}
#endif


#ifdef __NR_init_module
static asmlinkage long custom_init_module(void __user *umod, unsigned long len, const char __user *uargs)
{
    asmlinkage long (*org_init_module)(void __user *umod, unsigned long len, const char __user *uargs);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:init_module,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_init_module = (asmlinkage long (*)(void __user *umod, unsigned long len, const char __user *uargs)) org_sys_table[__NR_init_module];
    return org_init_module(umod, len, uargs);
}
#endif

#ifdef __NR_delete_module
static asmlinkage long custom_delete_module(const char __user *name_user, unsigned int flags)
{
    asmlinkage long (*org_delete_module)(const char __user *name_user, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:delete_module,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_delete_module = (asmlinkage long (*)(const char __user *name_user, unsigned int flags)) org_sys_table[__NR_delete_module];
    return org_delete_module(name_user, flags);
}
#endif


#ifdef CONFIG_OLD_SIGSUSPEND
#ifdef __NR_sigsuspend
static asmlinkage long custom_sigsuspend(old_sigset_t mask)
{
    asmlinkage long (*org_sigsuspend)(old_sigset_t mask);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sigsuspend,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sigsuspend = (asmlinkage long (*)(old_sigset_t mask)) org_sys_table[__NR_sigsuspend];
    return org_sigsuspend(mask);
}
#endif

#endif

#ifdef CONFIG_OLD_SIGSUSPEND3
#ifdef __NR_sigsuspend
static asmlinkage long custom_sigsuspend(int unused1, int unused2, old_sigset_t mask)
{
    asmlinkage long (*org_sigsuspend)(int unused1, int unused2, old_sigset_t mask);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sigsuspend,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sigsuspend = (asmlinkage long (*)(int unused1, int unused2, old_sigset_t mask)) org_sys_table[__NR_sigsuspend];
    return org_sigsuspend(unused1, unused2, mask);
}
#endif

#endif

#ifdef __NR_rt_sigsuspend
static asmlinkage long custom_rt_sigsuspend(sigset_t __user *unewset, size_t sigsetsize)
{
    asmlinkage long (*org_rt_sigsuspend)(sigset_t __user *unewset, size_t sigsetsize);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rt_sigsuspend,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rt_sigsuspend = (asmlinkage long (*)(sigset_t __user *unewset, size_t sigsetsize)) org_sys_table[__NR_rt_sigsuspend];
    return org_rt_sigsuspend(unewset, sigsetsize);
}
#endif


#ifdef CONFIG_OLD_SIGACTION
#ifdef __NR_sigaction
static asmlinkage long custom_sigaction(int signum, const struct old_sigaction __user *uact, struct old_sigaction __user *uoldact)
{
    asmlinkage long (*org_sigaction)(int signum, const struct old_sigaction __user *uact, struct old_sigaction __user *uoldact);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sigaction,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sigaction = (asmlinkage long (*)(int signum, const struct old_sigaction __user *uact, struct old_sigaction __user *uoldact)) org_sys_table[__NR_sigaction];
    return org_sigaction(signum, uact, uoldact);
}
#endif

#endif

#ifndef CONFIG_ODD_RT_SIGACTION
#ifdef __NR_rt_sigaction
static asmlinkage long custom_rt_sigaction(int signum, const struct sigaction __user *uact, struct sigaction __user *uoldact, size_t sigsetsize)
{
    asmlinkage long (*org_rt_sigaction)(int signum, const struct sigaction __user *uact, struct sigaction __user *uoldact, size_t sigsetsize);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rt_sigaction,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rt_sigaction = (asmlinkage long (*)(int signum, const struct sigaction __user *uact, struct sigaction __user *uoldact, size_t sigsetsize)) org_sys_table[__NR_rt_sigaction];
    return org_rt_sigaction(signum, uact, uoldact, sigsetsize);
}
#endif

#endif
#ifdef __NR_rt_sigprocmask
static asmlinkage long custom_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
{
    asmlinkage long (*org_rt_sigprocmask)(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rt_sigprocmask,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rt_sigprocmask = (asmlinkage long (*)(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)) org_sys_table[__NR_rt_sigprocmask];
    return org_rt_sigprocmask(how, set, oset, sigsetsize);
}
#endif

#ifdef __NR_rt_sigpending
static asmlinkage long custom_rt_sigpending(sigset_t __user *set, size_t sigsetsize)
{
    asmlinkage long (*org_rt_sigpending)(sigset_t __user *set, size_t sigsetsize);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rt_sigpending,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rt_sigpending = (asmlinkage long (*)(sigset_t __user *set, size_t sigsetsize)) org_sys_table[__NR_rt_sigpending];
    return org_rt_sigpending(set, sigsetsize);
}
#endif

#ifdef __NR_rt_sigtimedwait
static asmlinkage long custom_rt_sigtimedwait(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize)
{
    asmlinkage long (*org_rt_sigtimedwait)(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rt_sigtimedwait,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rt_sigtimedwait = (asmlinkage long (*)(const sigset_t __user *uthese, siginfo_t __user *uinfo, const struct timespec __user *uts, size_t sigsetsize)) org_sys_table[__NR_rt_sigtimedwait];
    return org_rt_sigtimedwait(uthese, uinfo, uts, sigsetsize);
}
#endif

#ifdef __NR_rt_tgsigqueueinfo
static asmlinkage long custom_rt_tgsigqueueinfo(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo)
{
    asmlinkage long (*org_rt_tgsigqueueinfo)(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rt_tgsigqueueinfo,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rt_tgsigqueueinfo = (asmlinkage long (*)(pid_t tgid, pid_t  pid, int sig, siginfo_t __user *uinfo)) org_sys_table[__NR_rt_tgsigqueueinfo];
    return org_rt_tgsigqueueinfo(tgid, pid, sig, uinfo);
}
#endif

#ifdef __NR_kill
static asmlinkage long custom_kill(pid_t pid, int sig)
{
    asmlinkage long (*org_kill)(pid_t pid, int sig);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:kill,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_kill = (asmlinkage long (*)(pid_t pid, int sig)) org_sys_table[__NR_kill];
    return org_kill(pid, sig);
}
#endif

#ifdef __NR_tgkill
static asmlinkage long custom_tgkill(pid_t tgid, pid_t pid, int sig)
{
    asmlinkage long (*org_tgkill)(pid_t tgid, pid_t pid, int sig);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:tgkill,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_tgkill = (asmlinkage long (*)(pid_t tgid, pid_t pid, int sig)) org_sys_table[__NR_tgkill];
    return org_tgkill(tgid, pid, sig);
}
#endif

#ifdef __NR_tkill
static asmlinkage long custom_tkill(pid_t pid, int sig)
{
    asmlinkage long (*org_tkill)(pid_t pid, int sig);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:tkill,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_tkill = (asmlinkage long (*)(pid_t pid, int sig)) org_sys_table[__NR_tkill];
    return org_tkill(pid, sig);
}
#endif

#ifdef __NR_rt_sigqueueinfo
static asmlinkage long custom_rt_sigqueueinfo(pid_t pid, int sig, siginfo_t __user *uinfo)
{
    asmlinkage long (*org_rt_sigqueueinfo)(pid_t pid, int sig, siginfo_t __user *uinfo);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rt_sigqueueinfo,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rt_sigqueueinfo = (asmlinkage long (*)(pid_t pid, int sig, siginfo_t __user *uinfo)) org_sys_table[__NR_rt_sigqueueinfo];
    return org_rt_sigqueueinfo(pid, sig, uinfo);
}
#endif

#ifdef __NR_sgetmask
static asmlinkage long custom_sgetmask(void)
{
    asmlinkage long (*org_sgetmask)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sgetmask,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sgetmask = (asmlinkage long (*)(void)) org_sys_table[__NR_sgetmask];
    return org_sgetmask();
}
#endif

#ifdef __NR_ssetmask
static asmlinkage long custom_ssetmask(int newmask)
{
    asmlinkage long (*org_ssetmask)(int newmask);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ssetmask,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ssetmask = (asmlinkage long (*)(int newmask)) org_sys_table[__NR_ssetmask];
    return org_ssetmask(newmask);
}
#endif

#ifdef __NR_signal
static asmlinkage long custom_signal(int sig, __sighandler_t handler)
{
    asmlinkage long (*org_signal)(int sig, __sighandler_t handler);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:signal,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_signal = (asmlinkage long (*)(int sig, __sighandler_t handler)) org_sys_table[__NR_signal];
    return org_signal(sig, handler);
}
#endif

#ifdef __NR_pause
static asmlinkage long custom_pause(void)
{
    asmlinkage long (*org_pause)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pause,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pause = (asmlinkage long (*)(void)) org_sys_table[__NR_pause];
    return org_pause();
}
#endif


#ifdef __NR_sync
static asmlinkage long custom_sync(void)
{
    asmlinkage long (*org_sync)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sync,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sync = (asmlinkage long (*)(void)) org_sys_table[__NR_sync];
    return org_sync();
}
#endif

#ifdef __NR_fsync
static asmlinkage long custom_fsync(unsigned int fd)
{
    asmlinkage long (*org_fsync)(unsigned int fd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fsync,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fsync = (asmlinkage long (*)(unsigned int fd)) org_sys_table[__NR_fsync];
    return org_fsync(fd);
}
#endif

#ifdef __NR_fdatasync
static asmlinkage long custom_fdatasync(unsigned int fd)
{
    asmlinkage long (*org_fdatasync)(unsigned int fd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fdatasync,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fdatasync = (asmlinkage long (*)(unsigned int fd)) org_sys_table[__NR_fdatasync];
    return org_fdatasync(fd);
}
#endif

#ifdef __NR_bdflush
static asmlinkage long custom_bdflush(int func, long data)
{
    asmlinkage long (*org_bdflush)(int func, long data);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:bdflush,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_bdflush = (asmlinkage long (*)(int func, long data)) org_sys_table[__NR_bdflush];
    return org_bdflush(func, data);
}
#endif

#ifdef __NR_mount
static asmlinkage long custom_mount(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)
{
    asmlinkage long (*org_mount)(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mount,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mount = (asmlinkage long (*)(char __user *dev_name, char __user *dir_name, char __user *type, unsigned long flags, void __user *data)) org_sys_table[__NR_mount];
    return org_mount(dev_name, dir_name, type, flags, data);
}
#endif

#ifdef __NR_umount
static asmlinkage long custom_umount(char __user *name, int flags)
{
    asmlinkage long (*org_umount)(char __user *name, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:umount,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_umount = (asmlinkage long (*)(char __user *name, int flags)) org_sys_table[__NR_umount];
    return org_umount(name, flags);
}
#endif

#ifdef __NR_oldumount
static asmlinkage long custom_oldumount(char __user *name)
{
    asmlinkage long (*org_oldumount)(char __user *name);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:oldumount,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_oldumount = (asmlinkage long (*)(char __user *name)) org_sys_table[__NR_oldumount];
    return org_oldumount(name);
}
#endif

#ifdef __NR_truncate
static asmlinkage long custom_truncate(const char __user *path, long length)
{
    asmlinkage long (*org_truncate)(const char __user *path, long length);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:truncate,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_truncate = (asmlinkage long (*)(const char __user *path, long length)) org_sys_table[__NR_truncate];
    return org_truncate(path, length);
}
#endif

#ifdef __NR_ftruncate
static asmlinkage long custom_ftruncate(unsigned int fd, unsigned long length)
{
    asmlinkage long (*org_ftruncate)(unsigned int fd, unsigned long length);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ftruncate,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ftruncate = (asmlinkage long (*)(unsigned int fd, unsigned long length)) org_sys_table[__NR_ftruncate];
    return org_ftruncate(fd, length);
}
#endif

#ifdef __NR_stat
static asmlinkage long custom_stat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    asmlinkage long (*org_stat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:stat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_stat = (asmlinkage long (*)(const char __user *filename, struct __old_kernel_stat __user *statbuf)) org_sys_table[__NR_stat];
    return org_stat(filename, statbuf);
}
#endif

#ifdef __NR_statfs
static asmlinkage long custom_statfs(const char __user * path, struct statfs __user *buf)
{
    asmlinkage long (*org_statfs)(const char __user * path, struct statfs __user *buf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:statfs,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_statfs = (asmlinkage long (*)(const char __user * path, struct statfs __user *buf)) org_sys_table[__NR_statfs];
    return org_statfs(path, buf);
}
#endif

#ifdef __NR_statfs64
static asmlinkage long custom_statfs64(const char __user *path, size_t sz, struct statfs64 __user *buf)
{
    asmlinkage long (*org_statfs64)(const char __user *path, size_t sz, struct statfs64 __user *buf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:statfs64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_statfs64 = (asmlinkage long (*)(const char __user *path, size_t sz, struct statfs64 __user *buf)) org_sys_table[__NR_statfs64];
    return org_statfs64(path, sz, buf);
}
#endif

#ifdef __NR_fstatfs
static asmlinkage long custom_fstatfs(unsigned int fd, struct statfs __user *buf)
{
    asmlinkage long (*org_fstatfs)(unsigned int fd, struct statfs __user *buf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fstatfs,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fstatfs = (asmlinkage long (*)(unsigned int fd, struct statfs __user *buf)) org_sys_table[__NR_fstatfs];
    return org_fstatfs(fd, buf);
}
#endif

#ifdef __NR_fstatfs64
static asmlinkage long custom_fstatfs64(unsigned int fd, size_t sz, struct statfs64 __user *buf)
{
    asmlinkage long (*org_fstatfs64)(unsigned int fd, size_t sz, struct statfs64 __user *buf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fstatfs64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fstatfs64 = (asmlinkage long (*)(unsigned int fd, size_t sz, struct statfs64 __user *buf)) org_sys_table[__NR_fstatfs64];
    return org_fstatfs64(fd, sz, buf);
}
#endif

#ifdef __NR_lstat
static asmlinkage long custom_lstat(const char __user *filename, struct __old_kernel_stat __user *statbuf)
{
    asmlinkage long (*org_lstat)(const char __user *filename, struct __old_kernel_stat __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lstat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lstat = (asmlinkage long (*)(const char __user *filename, struct __old_kernel_stat __user *statbuf)) org_sys_table[__NR_lstat];
    return org_lstat(filename, statbuf);
}
#endif

#ifdef __NR_fstat
static asmlinkage long custom_fstat(unsigned int fd, struct __old_kernel_stat __user *statbuf)
{
    asmlinkage long (*org_fstat)(unsigned int fd, struct __old_kernel_stat __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fstat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fstat = (asmlinkage long (*)(unsigned int fd, struct __old_kernel_stat __user *statbuf)) org_sys_table[__NR_fstat];
    return org_fstat(fd, statbuf);
}
#endif

#ifdef __NR_newstat
static asmlinkage long custom_newstat(const char __user *filename, struct stat __user *statbuf)
{
    asmlinkage long (*org_newstat)(const char __user *filename, struct stat __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:newstat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_newstat = (asmlinkage long (*)(const char __user *filename, struct stat __user *statbuf)) org_sys_table[__NR_newstat];
    return org_newstat(filename, statbuf);
}
#endif

#ifdef __NR_newlstat
static asmlinkage long custom_newlstat(const char __user *filename, struct stat __user *statbuf)
{
    asmlinkage long (*org_newlstat)(const char __user *filename, struct stat __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:newlstat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_newlstat = (asmlinkage long (*)(const char __user *filename, struct stat __user *statbuf)) org_sys_table[__NR_newlstat];
    return org_newlstat(filename, statbuf);
}
#endif

#ifdef __NR_newfstat
static asmlinkage long custom_newfstat(unsigned int fd, struct stat __user *statbuf)
{
    asmlinkage long (*org_newfstat)(unsigned int fd, struct stat __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:newfstat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_newfstat = (asmlinkage long (*)(unsigned int fd, struct stat __user *statbuf)) org_sys_table[__NR_newfstat];
    return org_newfstat(fd, statbuf);
}
#endif

#ifdef __NR_ustat
static asmlinkage long custom_ustat(unsigned dev, struct ustat __user *ubuf)
{
    asmlinkage long (*org_ustat)(unsigned dev, struct ustat __user *ubuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ustat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ustat = (asmlinkage long (*)(unsigned dev, struct ustat __user *ubuf)) org_sys_table[__NR_ustat];
    return org_ustat(dev, ubuf);
}
#endif

#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef __NR_stat64
static asmlinkage long custom_stat64(const char __user *filename, struct stat64 __user *statbuf)
{
    asmlinkage long (*org_stat64)(const char __user *filename, struct stat64 __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:stat64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_stat64 = (asmlinkage long (*)(const char __user *filename, struct stat64 __user *statbuf)) org_sys_table[__NR_stat64];
    return org_stat64(filename, statbuf);
}
#endif

#ifdef __NR_fstat64
static asmlinkage long custom_fstat64(unsigned long fd, struct stat64 __user *statbuf)
{
    asmlinkage long (*org_fstat64)(unsigned long fd, struct stat64 __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fstat64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fstat64 = (asmlinkage long (*)(unsigned long fd, struct stat64 __user *statbuf)) org_sys_table[__NR_fstat64];
    return org_fstat64(fd, statbuf);
}
#endif

#ifdef __NR_lstat64
static asmlinkage long custom_lstat64(const char __user *filename, struct stat64 __user *statbuf)
{
    asmlinkage long (*org_lstat64)(const char __user *filename, struct stat64 __user *statbuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lstat64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lstat64 = (asmlinkage long (*)(const char __user *filename, struct stat64 __user *statbuf)) org_sys_table[__NR_lstat64];
    return org_lstat64(filename, statbuf);
}
#endif

#ifdef __NR_fstatat64
static asmlinkage long custom_fstatat64(int dfd, const char __user *filename, struct stat64 __user *statbuf, int flag)
{
    asmlinkage long (*org_fstatat64)(int dfd, const char __user *filename, struct stat64 __user *statbuf, int flag);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fstatat64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fstatat64 = (asmlinkage long (*)(int dfd, const char __user *filename, struct stat64 __user *statbuf, int flag)) org_sys_table[__NR_fstatat64];
    return org_fstatat64(dfd, filename, statbuf, flag);
}
#endif

#endif
#if BITS_PER_LONG == 32
#ifdef __NR_truncate64
static asmlinkage long custom_truncate64(const char __user *path, loff_t length)
{
    asmlinkage long (*org_truncate64)(const char __user *path, loff_t length);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:truncate64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_truncate64 = (asmlinkage long (*)(const char __user *path, loff_t length)) org_sys_table[__NR_truncate64];
    return org_truncate64(path, length);
}
#endif

#ifdef __NR_ftruncate64
static asmlinkage long custom_ftruncate64(unsigned int fd, loff_t length)
{
    asmlinkage long (*org_ftruncate64)(unsigned int fd, loff_t length);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ftruncate64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ftruncate64 = (asmlinkage long (*)(unsigned int fd, loff_t length)) org_sys_table[__NR_ftruncate64];
    return org_ftruncate64(fd, length);
}
#endif

#endif

#ifdef __NR_setxattr
static asmlinkage long custom_setxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags)
{
    asmlinkage long (*org_setxattr)(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setxattr = (asmlinkage long (*)(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags)) org_sys_table[__NR_setxattr];
    return org_setxattr(path, name, value, size, flags);
}
#endif

#ifdef __NR_lsetxattr
static asmlinkage long custom_lsetxattr(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags)
{
    asmlinkage long (*org_lsetxattr)(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lsetxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lsetxattr = (asmlinkage long (*)(const char __user *path, const char __user *name, const void __user *value, size_t size, int flags)) org_sys_table[__NR_lsetxattr];
    return org_lsetxattr(path, name, value, size, flags);
}
#endif

#ifdef __NR_fsetxattr
static asmlinkage long custom_fsetxattr(int fd, const char __user *name, const void __user *value, size_t size, int flags)
{
    asmlinkage long (*org_fsetxattr)(int fd, const char __user *name, const void __user *value, size_t size, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fsetxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fsetxattr = (asmlinkage long (*)(int fd, const char __user *name, const void __user *value, size_t size, int flags)) org_sys_table[__NR_fsetxattr];
    return org_fsetxattr(fd, name, value, size, flags);
}
#endif

#ifdef __NR_getxattr
static asmlinkage long custom_getxattr(const char __user *path, const char __user *name, void __user *value, size_t size)
{
    asmlinkage long (*org_getxattr)(const char __user *path, const char __user *name, void __user *value, size_t size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getxattr = (asmlinkage long (*)(const char __user *path, const char __user *name, void __user *value, size_t size)) org_sys_table[__NR_getxattr];
    return org_getxattr(path, name, value, size);
}
#endif

#ifdef __NR_lgetxattr
static asmlinkage long custom_lgetxattr(const char __user *path, const char __user *name, void __user *value, size_t size)
{
    asmlinkage long (*org_lgetxattr)(const char __user *path, const char __user *name, void __user *value, size_t size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lgetxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lgetxattr = (asmlinkage long (*)(const char __user *path, const char __user *name, void __user *value, size_t size)) org_sys_table[__NR_lgetxattr];
    return org_lgetxattr(path, name, value, size);
}
#endif

#ifdef __NR_fgetxattr
static asmlinkage long custom_fgetxattr(int fd, const char __user *name, void __user *value, size_t size)
{
    asmlinkage long (*org_fgetxattr)(int fd, const char __user *name, void __user *value, size_t size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fgetxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fgetxattr = (asmlinkage long (*)(int fd, const char __user *name, void __user *value, size_t size)) org_sys_table[__NR_fgetxattr];
    return org_fgetxattr(fd, name, value, size);
}
#endif

#ifdef __NR_listxattr
static asmlinkage long custom_listxattr(const char __user *path, char __user *list, size_t size)
{
    asmlinkage long (*org_listxattr)(const char __user *path, char __user *list, size_t size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:listxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_listxattr = (asmlinkage long (*)(const char __user *path, char __user *list, size_t size)) org_sys_table[__NR_listxattr];
    return org_listxattr(path, list, size);
}
#endif

#ifdef __NR_llistxattr
static asmlinkage long custom_llistxattr(const char __user *path, char __user *list, size_t size)
{
    asmlinkage long (*org_llistxattr)(const char __user *path, char __user *list, size_t size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:llistxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_llistxattr = (asmlinkage long (*)(const char __user *path, char __user *list, size_t size)) org_sys_table[__NR_llistxattr];
    return org_llistxattr(path, list, size);
}
#endif

#ifdef __NR_flistxattr
static asmlinkage long custom_flistxattr(int fd, char __user *list, size_t size)
{
    asmlinkage long (*org_flistxattr)(int fd, char __user *list, size_t size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:flistxattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_flistxattr = (asmlinkage long (*)(int fd, char __user *list, size_t size)) org_sys_table[__NR_flistxattr];
    return org_flistxattr(fd, list, size);
}
#endif

#ifdef __NR_removexattr
static asmlinkage long custom_removexattr(const char __user *path, const char __user *name)
{
    asmlinkage long (*org_removexattr)(const char __user *path, const char __user *name);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:removexattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_removexattr = (asmlinkage long (*)(const char __user *path, const char __user *name)) org_sys_table[__NR_removexattr];
    return org_removexattr(path, name);
}
#endif

#ifdef __NR_lremovexattr
static asmlinkage long custom_lremovexattr(const char __user *path, const char __user *name)
{
    asmlinkage long (*org_lremovexattr)(const char __user *path, const char __user *name);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lremovexattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lremovexattr = (asmlinkage long (*)(const char __user *path, const char __user *name)) org_sys_table[__NR_lremovexattr];
    return org_lremovexattr(path, name);
}
#endif

#ifdef __NR_fremovexattr
static asmlinkage long custom_fremovexattr(int fd, const char __user *name)
{
    asmlinkage long (*org_fremovexattr)(int fd, const char __user *name);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fremovexattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fremovexattr = (asmlinkage long (*)(int fd, const char __user *name)) org_sys_table[__NR_fremovexattr];
    return org_fremovexattr(fd, name);
}
#endif


#ifdef __NR_brk
static asmlinkage long custom_brk(unsigned long brk)
{
    asmlinkage long (*org_brk)(unsigned long brk);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:brk,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_brk = (asmlinkage long (*)(unsigned long brk)) org_sys_table[__NR_brk];
    return org_brk(brk);
}
#endif

#ifdef __NR_mprotect
static asmlinkage long custom_mprotect(unsigned long start, size_t len, unsigned long prot)
{
    asmlinkage long (*org_mprotect)(unsigned long start, size_t len, unsigned long prot);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mprotect,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mprotect = (asmlinkage long (*)(unsigned long start, size_t len, unsigned long prot)) org_sys_table[__NR_mprotect];
    return org_mprotect(start, len, prot);
}
#endif

#ifdef __NR_mremap
static asmlinkage long custom_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
    asmlinkage long (*org_mremap)(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mremap,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mremap = (asmlinkage long (*)(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)) org_sys_table[__NR_mremap];
    return org_mremap(addr, old_len, new_len, flags, new_addr);
}
#endif

#ifdef __NR_remap_file_pages
static asmlinkage long custom_remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
    asmlinkage long (*org_remap_file_pages)(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:remap_file_pages,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_remap_file_pages = (asmlinkage long (*)(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)) org_sys_table[__NR_remap_file_pages];
    return org_remap_file_pages(start, size, prot, pgoff, flags);
}
#endif

#ifdef __NR_msync
static asmlinkage long custom_msync(unsigned long start, size_t len, int flags)
{
    asmlinkage long (*org_msync)(unsigned long start, size_t len, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:msync,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_msync = (asmlinkage long (*)(unsigned long start, size_t len, int flags)) org_sys_table[__NR_msync];
    return org_msync(start, len, flags);
}
#endif

#ifdef __NR_fadvise64
static asmlinkage long custom_fadvise64(int fd, loff_t offset, size_t len, int advice)
{
    asmlinkage long (*org_fadvise64)(int fd, loff_t offset, size_t len, int advice);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fadvise64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fadvise64 = (asmlinkage long (*)(int fd, loff_t offset, size_t len, int advice)) org_sys_table[__NR_fadvise64];
    return org_fadvise64(fd, offset, len, advice);
}
#endif

#ifdef __NR_fadvise64_64
static asmlinkage long custom_fadvise64_64(int fd, loff_t offset, loff_t len, int advice)
{
    asmlinkage long (*org_fadvise64_64)(int fd, loff_t offset, loff_t len, int advice);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fadvise64_64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fadvise64_64 = (asmlinkage long (*)(int fd, loff_t offset, loff_t len, int advice)) org_sys_table[__NR_fadvise64_64];
    return org_fadvise64_64(fd, offset, len, advice);
}
#endif

#ifdef __NR_munmap
static asmlinkage long custom_munmap(unsigned long addr, size_t len)
{
    asmlinkage long (*org_munmap)(unsigned long addr, size_t len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:munmap,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_munmap = (asmlinkage long (*)(unsigned long addr, size_t len)) org_sys_table[__NR_munmap];
    return org_munmap(addr, len);
}
#endif

#ifdef __NR_mlock
static asmlinkage long custom_mlock(unsigned long start, size_t len)
{
    asmlinkage long (*org_mlock)(unsigned long start, size_t len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mlock,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mlock = (asmlinkage long (*)(unsigned long start, size_t len)) org_sys_table[__NR_mlock];
    return org_mlock(start, len);
}
#endif

#ifdef __NR_munlock
static asmlinkage long custom_munlock(unsigned long start, size_t len)
{
    asmlinkage long (*org_munlock)(unsigned long start, size_t len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:munlock,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_munlock = (asmlinkage long (*)(unsigned long start, size_t len)) org_sys_table[__NR_munlock];
    return org_munlock(start, len);
}
#endif

#ifdef __NR_mlockall
static asmlinkage long custom_mlockall(int flags)
{
    asmlinkage long (*org_mlockall)(int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mlockall,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mlockall = (asmlinkage long (*)(int flags)) org_sys_table[__NR_mlockall];
    return org_mlockall(flags);
}
#endif

#ifdef __NR_munlockall
static asmlinkage long custom_munlockall(void)
{
    asmlinkage long (*org_munlockall)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:munlockall,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_munlockall = (asmlinkage long (*)(void)) org_sys_table[__NR_munlockall];
    return org_munlockall();
}
#endif

#ifdef __NR_madvise
static asmlinkage long custom_madvise(unsigned long start, size_t len, int behavior)
{
    asmlinkage long (*org_madvise)(unsigned long start, size_t len, int behavior);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:madvise,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_madvise = (asmlinkage long (*)(unsigned long start, size_t len, int behavior)) org_sys_table[__NR_madvise];
    return org_madvise(start, len, behavior);
}
#endif

#ifdef __NR_mincore
static asmlinkage long custom_mincore(unsigned long start, size_t len, unsigned char __user * vec)
{
    asmlinkage long (*org_mincore)(unsigned long start, size_t len, unsigned char __user * vec);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mincore,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mincore = (asmlinkage long (*)(unsigned long start, size_t len, unsigned char __user * vec)) org_sys_table[__NR_mincore];
    return org_mincore(start, len, vec);
}
#endif


#ifdef __NR_pivot_root
static asmlinkage long custom_pivot_root(const char __user *new_root, const char __user *put_old)
{
    asmlinkage long (*org_pivot_root)(const char __user *new_root, const char __user *put_old);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pivot_root,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pivot_root = (asmlinkage long (*)(const char __user *new_root, const char __user *put_old)) org_sys_table[__NR_pivot_root];
    return org_pivot_root(new_root, put_old);
}
#endif

#ifdef __NR_chroot
static asmlinkage long custom_chroot(const char __user *filename)
{
    asmlinkage long (*org_chroot)(const char __user *filename);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:chroot,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_chroot = (asmlinkage long (*)(const char __user *filename)) org_sys_table[__NR_chroot];
    return org_chroot(filename);
}
#endif

#ifdef __NR_mknod
static asmlinkage long custom_mknod(const char __user *filename, umode_t mode, unsigned dev)
{
    asmlinkage long (*org_mknod)(const char __user *filename, umode_t mode, unsigned dev);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mknod,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mknod = (asmlinkage long (*)(const char __user *filename, umode_t mode, unsigned dev)) org_sys_table[__NR_mknod];
    return org_mknod(filename, mode, dev);
}
#endif

#ifdef __NR_link
static asmlinkage long custom_link(const char __user *oldname, const char __user *newname)
{
    asmlinkage long (*org_link)(const char __user *oldname, const char __user *newname);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:link,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_link = (asmlinkage long (*)(const char __user *oldname, const char __user *newname)) org_sys_table[__NR_link];
    return org_link(oldname, newname);
}
#endif

#ifdef __NR_symlink
static asmlinkage long custom_symlink(const char __user *old, const char __user *new)
{
    asmlinkage long (*org_symlink)(const char __user *old, const char __user *new);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:symlink,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_symlink = (asmlinkage long (*)(const char __user *old, const char __user *new)) org_sys_table[__NR_symlink];
    return org_symlink(old, new);
}
#endif

#ifdef __NR_unlink
static asmlinkage long custom_unlink(const char __user *pathname)
{
    asmlinkage long (*org_unlink)(const char __user *pathname);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:unlink,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_unlink = (asmlinkage long (*)(const char __user *pathname)) org_sys_table[__NR_unlink];
    return org_unlink(pathname);
}
#endif

#ifdef __NR_rename
static asmlinkage long custom_rename(const char __user *oldname, const char __user *newname)
{
    asmlinkage long (*org_rename)(const char __user *oldname, const char __user *newname);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rename,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rename = (asmlinkage long (*)(const char __user *oldname, const char __user *newname)) org_sys_table[__NR_rename];
    return org_rename(oldname, newname);
}
#endif

#ifdef __NR_chmod
static asmlinkage long custom_chmod(const char __user *filename, umode_t mode)
{
    asmlinkage long (*org_chmod)(const char __user *filename, umode_t mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:chmod,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_chmod = (asmlinkage long (*)(const char __user *filename, umode_t mode)) org_sys_table[__NR_chmod];
    return org_chmod(filename, mode);
}
#endif

#ifdef __NR_fchmod
static asmlinkage long custom_fchmod(unsigned int fd, umode_t mode)
{
    asmlinkage long (*org_fchmod)(unsigned int fd, umode_t mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fchmod,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fchmod = (asmlinkage long (*)(unsigned int fd, umode_t mode)) org_sys_table[__NR_fchmod];
    return org_fchmod(fd, mode);
}
#endif


#ifdef __NR_fcntl
static asmlinkage long custom_fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    asmlinkage long (*org_fcntl)(unsigned int fd, unsigned int cmd, unsigned long arg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fcntl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fcntl = (asmlinkage long (*)(unsigned int fd, unsigned int cmd, unsigned long arg)) org_sys_table[__NR_fcntl];
    return org_fcntl(fd, cmd, arg);
}
#endif

#if BITS_PER_LONG == 32
#ifdef __NR_fcntl64
static asmlinkage long custom_fcntl64(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    asmlinkage long (*org_fcntl64)(unsigned int fd, unsigned int cmd, unsigned long arg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fcntl64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fcntl64 = (asmlinkage long (*)(unsigned int fd, unsigned int cmd, unsigned long arg)) org_sys_table[__NR_fcntl64];
    return org_fcntl64(fd, cmd, arg);
}
#endif

#endif
#ifdef __NR_pipe
static asmlinkage long custom_pipe(int __user *fildes)
{
    asmlinkage long (*org_pipe)(int __user *fildes);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pipe,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pipe = (asmlinkage long (*)(int __user *fildes)) org_sys_table[__NR_pipe];
    return org_pipe(fildes);
}
#endif

#ifdef __NR_pipe2
static asmlinkage long custom_pipe2(int __user *fildes, int flags)
{
    asmlinkage long (*org_pipe2)(int __user *fildes, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pipe2,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pipe2 = (asmlinkage long (*)(int __user *fildes, int flags)) org_sys_table[__NR_pipe2];
    return org_pipe2(fildes, flags);
}
#endif

#ifdef __NR_dup
static asmlinkage long custom_dup(unsigned int fildes)
{
    asmlinkage long (*org_dup)(unsigned int fildes);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:dup,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_dup = (asmlinkage long (*)(unsigned int fildes)) org_sys_table[__NR_dup];
    return org_dup(fildes);
}
#endif

#ifdef __NR_dup2
static asmlinkage long custom_dup2(unsigned int oldfd, unsigned int newfd)
{
    asmlinkage long (*org_dup2)(unsigned int oldfd, unsigned int newfd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:dup2,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_dup2 = (asmlinkage long (*)(unsigned int oldfd, unsigned int newfd)) org_sys_table[__NR_dup2];
    return org_dup2(oldfd, newfd);
}
#endif

#ifdef __NR_dup3
static asmlinkage long custom_dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
    asmlinkage long (*org_dup3)(unsigned int oldfd, unsigned int newfd, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:dup3,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_dup3 = (asmlinkage long (*)(unsigned int oldfd, unsigned int newfd, int flags)) org_sys_table[__NR_dup3];
    return org_dup3(oldfd, newfd, flags);
}
#endif

#ifdef __NR_ioperm
static asmlinkage long custom_ioperm(unsigned long from, unsigned long num, int on)
{
    asmlinkage long (*org_ioperm)(unsigned long from, unsigned long num, int on);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ioperm,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ioperm = (asmlinkage long (*)(unsigned long from, unsigned long num, int on)) org_sys_table[__NR_ioperm];
    return org_ioperm(from, num, on);
}
#endif

#ifdef __NR_ioctl
static asmlinkage long custom_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    asmlinkage long (*org_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ioctl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ioctl = (asmlinkage long (*)(unsigned int fd, unsigned int cmd, unsigned long arg)) org_sys_table[__NR_ioctl];
    return org_ioctl(fd, cmd, arg);
}
#endif

#ifdef __NR_flock
static asmlinkage long custom_flock(unsigned int fd, unsigned int cmd)
{
    asmlinkage long (*org_flock)(unsigned int fd, unsigned int cmd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:flock,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_flock = (asmlinkage long (*)(unsigned int fd, unsigned int cmd)) org_sys_table[__NR_flock];
    return org_flock(fd, cmd);
}
#endif

#ifdef __NR_io_setup
static asmlinkage long custom_io_setup(unsigned nr_reqs, aio_context_t __user *ctx)
{
    asmlinkage long (*org_io_setup)(unsigned nr_reqs, aio_context_t __user *ctx);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:io_setup,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_io_setup = (asmlinkage long (*)(unsigned nr_reqs, aio_context_t __user *ctx)) org_sys_table[__NR_io_setup];
    return org_io_setup(nr_reqs, ctx);
}
#endif

#ifdef __NR_io_destroy
static asmlinkage long custom_io_destroy(aio_context_t ctx)
{
    asmlinkage long (*org_io_destroy)(aio_context_t ctx);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:io_destroy,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_io_destroy = (asmlinkage long (*)(aio_context_t ctx)) org_sys_table[__NR_io_destroy];
    return org_io_destroy(ctx);
}
#endif

#ifdef __NR_io_getevents
static asmlinkage long custom_io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)
{
    asmlinkage long (*org_io_getevents)(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:io_getevents,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_io_getevents = (asmlinkage long (*)(aio_context_t ctx_id, long min_nr, long nr, struct io_event __user *events, struct timespec __user *timeout)) org_sys_table[__NR_io_getevents];
    return org_io_getevents(ctx_id, min_nr, nr, events, timeout);
}
#endif

#ifdef __NR_io_submit
static asmlinkage long custom_io_submit(aio_context_t ctx_id, long nr, struct iocb __user * __user *uiocbpp)
{
    asmlinkage long (*org_io_submit)(aio_context_t ctx_id, long nr, struct iocb __user * __user *uiocbpp);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:io_submit,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_io_submit = (asmlinkage long (*)(aio_context_t ctx_id, long nr, struct iocb __user * __user *uiocbpp)) org_sys_table[__NR_io_submit];
    return org_io_submit(ctx_id, nr, uiocbpp);
}
#endif

#ifdef __NR_io_cancel
static asmlinkage long custom_io_cancel(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result)
{
    asmlinkage long (*org_io_cancel)(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:io_cancel,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_io_cancel = (asmlinkage long (*)(aio_context_t ctx_id, struct iocb __user *iocb, struct io_event __user *result)) org_sys_table[__NR_io_cancel];
    return org_io_cancel(ctx_id, iocb, result);
}
#endif

#ifdef __NR_sendfile
static asmlinkage long custom_sendfile(int out_fd, int in_fd, off_t __user *offset, size_t count)
{
    asmlinkage long (*org_sendfile)(int out_fd, int in_fd, off_t __user *offset, size_t count);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sendfile,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sendfile = (asmlinkage long (*)(int out_fd, int in_fd, off_t __user *offset, size_t count)) org_sys_table[__NR_sendfile];
    return org_sendfile(out_fd, in_fd, offset, count);
}
#endif

#ifdef __NR_sendfile64
static asmlinkage long custom_sendfile64(int out_fd, int in_fd, loff_t __user *offset, size_t count)
{
    asmlinkage long (*org_sendfile64)(int out_fd, int in_fd, loff_t __user *offset, size_t count);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sendfile64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sendfile64 = (asmlinkage long (*)(int out_fd, int in_fd, loff_t __user *offset, size_t count)) org_sys_table[__NR_sendfile64];
    return org_sendfile64(out_fd, in_fd, offset, count);
}
#endif

#ifdef __NR_readlink
static asmlinkage long custom_readlink(const char __user *path, char __user *buf, int bufsiz)
{
    asmlinkage long (*org_readlink)(const char __user *path, char __user *buf, int bufsiz);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:readlink,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_readlink = (asmlinkage long (*)(const char __user *path, char __user *buf, int bufsiz)) org_sys_table[__NR_readlink];
    return org_readlink(path, buf, bufsiz);
}
#endif

#ifdef __NR_creat
static asmlinkage long custom_creat(const char __user *pathname, umode_t mode)
{
    asmlinkage long (*org_creat)(const char __user *pathname, umode_t mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:creat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_creat = (asmlinkage long (*)(const char __user *pathname, umode_t mode)) org_sys_table[__NR_creat];
    return org_creat(pathname, mode);
}
#endif

#ifdef __NR_open
static asmlinkage long custom_open(const char __user *filename, int flags, umode_t mode)
{
    asmlinkage long (*org_open)(const char __user *filename, int flags, umode_t mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:open,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_open = (asmlinkage long (*)(const char __user *filename, int flags, umode_t mode)) org_sys_table[__NR_open];
    return org_open(filename, flags, mode);
}
#endif

#ifdef __NR_close
static asmlinkage long custom_close(unsigned int fd)
{
    asmlinkage long (*org_close)(unsigned int fd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:close,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_close = (asmlinkage long (*)(unsigned int fd)) org_sys_table[__NR_close];
    return org_close(fd);
}
#endif

#ifdef __NR_access
static asmlinkage long custom_access(const char __user *filename, int mode)
{
    asmlinkage long (*org_access)(const char __user *filename, int mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:access,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_access = (asmlinkage long (*)(const char __user *filename, int mode)) org_sys_table[__NR_access];
    return org_access(filename, mode);
}
#endif

#ifdef __NR_vhangup
static asmlinkage long custom_vhangup(void)
{
    asmlinkage long (*org_vhangup)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:vhangup,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_vhangup = (asmlinkage long (*)(void)) org_sys_table[__NR_vhangup];
    return org_vhangup();
}
#endif

#ifdef __NR_chown
static asmlinkage long custom_chown(const char __user *filename, uid_t user, gid_t group)
{
    asmlinkage long (*org_chown)(const char __user *filename, uid_t user, gid_t group);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:chown,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_chown = (asmlinkage long (*)(const char __user *filename, uid_t user, gid_t group)) org_sys_table[__NR_chown];
    return org_chown(filename, user, group);
}
#endif

#ifdef __NR_lchown
static asmlinkage long custom_lchown(const char __user *filename, uid_t user, gid_t group)
{
    asmlinkage long (*org_lchown)(const char __user *filename, uid_t user, gid_t group);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lchown,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lchown = (asmlinkage long (*)(const char __user *filename, uid_t user, gid_t group)) org_sys_table[__NR_lchown];
    return org_lchown(filename, user, group);
}
#endif

#ifdef __NR_fchown
static asmlinkage long custom_fchown(unsigned int fd, uid_t user, gid_t group)
{
    asmlinkage long (*org_fchown)(unsigned int fd, uid_t user, gid_t group);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fchown,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fchown = (asmlinkage long (*)(unsigned int fd, uid_t user, gid_t group)) org_sys_table[__NR_fchown];
    return org_fchown(fd, user, group);
}
#endif

#ifdef CONFIG_HAVE_UID16
#ifdef __NR_chown16
static asmlinkage long custom_chown16(const char __user *filename, old_uid_t user, old_gid_t group)
{
    asmlinkage long (*org_chown16)(const char __user *filename, old_uid_t user, old_gid_t group);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:chown16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_chown16 = (asmlinkage long (*)(const char __user *filename, old_uid_t user, old_gid_t group)) org_sys_table[__NR_chown16];
    return org_chown16(filename, user, group);
}
#endif

#ifdef __NR_lchown16
static asmlinkage long custom_lchown16(const char __user *filename, old_uid_t user, old_gid_t group)
{
    asmlinkage long (*org_lchown16)(const char __user *filename, old_uid_t user, old_gid_t group);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lchown16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lchown16 = (asmlinkage long (*)(const char __user *filename, old_uid_t user, old_gid_t group)) org_sys_table[__NR_lchown16];
    return org_lchown16(filename, user, group);
}
#endif

#ifdef __NR_fchown16
static asmlinkage long custom_fchown16(unsigned int fd, old_uid_t user, old_gid_t group)
{
    asmlinkage long (*org_fchown16)(unsigned int fd, old_uid_t user, old_gid_t group);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fchown16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fchown16 = (asmlinkage long (*)(unsigned int fd, old_uid_t user, old_gid_t group)) org_sys_table[__NR_fchown16];
    return org_fchown16(fd, user, group);
}
#endif

#ifdef __NR_setregid16
static asmlinkage long custom_setregid16(old_gid_t rgid, old_gid_t egid)
{
    asmlinkage long (*org_setregid16)(old_gid_t rgid, old_gid_t egid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setregid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setregid16 = (asmlinkage long (*)(old_gid_t rgid, old_gid_t egid)) org_sys_table[__NR_setregid16];
    return org_setregid16(rgid, egid);
}
#endif

#ifdef __NR_setgid16
static asmlinkage long custom_setgid16(old_gid_t gid)
{
    asmlinkage long (*org_setgid16)(old_gid_t gid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setgid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setgid16 = (asmlinkage long (*)(old_gid_t gid)) org_sys_table[__NR_setgid16];
    return org_setgid16(gid);
}
#endif

#ifdef __NR_setreuid16
static asmlinkage long custom_setreuid16(old_uid_t ruid, old_uid_t euid)
{
    asmlinkage long (*org_setreuid16)(old_uid_t ruid, old_uid_t euid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setreuid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setreuid16 = (asmlinkage long (*)(old_uid_t ruid, old_uid_t euid)) org_sys_table[__NR_setreuid16];
    return org_setreuid16(ruid, euid);
}
#endif

#ifdef __NR_setuid16
static asmlinkage long custom_setuid16(old_uid_t uid)
{
    asmlinkage long (*org_setuid16)(old_uid_t uid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setuid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setuid16 = (asmlinkage long (*)(old_uid_t uid)) org_sys_table[__NR_setuid16];
    return org_setuid16(uid);
}
#endif

#ifdef __NR_setresuid16
static asmlinkage long custom_setresuid16(old_uid_t ruid, old_uid_t euid, old_uid_t suid)
{
    asmlinkage long (*org_setresuid16)(old_uid_t ruid, old_uid_t euid, old_uid_t suid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setresuid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setresuid16 = (asmlinkage long (*)(old_uid_t ruid, old_uid_t euid, old_uid_t suid)) org_sys_table[__NR_setresuid16];
    return org_setresuid16(ruid, euid, suid);
}
#endif

#ifdef __NR_getresuid16
static asmlinkage long custom_getresuid16(old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid)
{
    asmlinkage long (*org_getresuid16)(old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getresuid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getresuid16 = (asmlinkage long (*)(old_uid_t __user *ruid, old_uid_t __user *euid, old_uid_t __user *suid)) org_sys_table[__NR_getresuid16];
    return org_getresuid16(ruid, euid, suid);
}
#endif

#ifdef __NR_setresgid16
static asmlinkage long custom_setresgid16(old_gid_t rgid, old_gid_t egid, old_gid_t sgid)
{
    asmlinkage long (*org_setresgid16)(old_gid_t rgid, old_gid_t egid, old_gid_t sgid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setresgid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setresgid16 = (asmlinkage long (*)(old_gid_t rgid, old_gid_t egid, old_gid_t sgid)) org_sys_table[__NR_setresgid16];
    return org_setresgid16(rgid, egid, sgid);
}
#endif

#ifdef __NR_getresgid16
static asmlinkage long custom_getresgid16(old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid)
{
    asmlinkage long (*org_getresgid16)(old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getresgid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getresgid16 = (asmlinkage long (*)(old_gid_t __user *rgid, old_gid_t __user *egid, old_gid_t __user *sgid)) org_sys_table[__NR_getresgid16];
    return org_getresgid16(rgid, egid, sgid);
}
#endif

#ifdef __NR_setfsuid16
static asmlinkage long custom_setfsuid16(old_uid_t uid)
{
    asmlinkage long (*org_setfsuid16)(old_uid_t uid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setfsuid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setfsuid16 = (asmlinkage long (*)(old_uid_t uid)) org_sys_table[__NR_setfsuid16];
    return org_setfsuid16(uid);
}
#endif

#ifdef __NR_setfsgid16
static asmlinkage long custom_setfsgid16(old_gid_t gid)
{
    asmlinkage long (*org_setfsgid16)(old_gid_t gid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setfsgid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setfsgid16 = (asmlinkage long (*)(old_gid_t gid)) org_sys_table[__NR_setfsgid16];
    return org_setfsgid16(gid);
}
#endif

#ifdef __NR_getgroups16
static asmlinkage long custom_getgroups16(int gidsetsize, old_gid_t __user *grouplist)
{
    asmlinkage long (*org_getgroups16)(int gidsetsize, old_gid_t __user *grouplist);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getgroups16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getgroups16 = (asmlinkage long (*)(int gidsetsize, old_gid_t __user *grouplist)) org_sys_table[__NR_getgroups16];
    return org_getgroups16(gidsetsize, grouplist);
}
#endif

#ifdef __NR_setgroups16
static asmlinkage long custom_setgroups16(int gidsetsize, old_gid_t __user *grouplist)
{
    asmlinkage long (*org_setgroups16)(int gidsetsize, old_gid_t __user *grouplist);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setgroups16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setgroups16 = (asmlinkage long (*)(int gidsetsize, old_gid_t __user *grouplist)) org_sys_table[__NR_setgroups16];
    return org_setgroups16(gidsetsize, grouplist);
}
#endif

#ifdef __NR_getuid16
static asmlinkage long custom_getuid16(void)
{
    asmlinkage long (*org_getuid16)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getuid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getuid16 = (asmlinkage long (*)(void)) org_sys_table[__NR_getuid16];
    return org_getuid16();
}
#endif

#ifdef __NR_geteuid16
static asmlinkage long custom_geteuid16(void)
{
    asmlinkage long (*org_geteuid16)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:geteuid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_geteuid16 = (asmlinkage long (*)(void)) org_sys_table[__NR_geteuid16];
    return org_geteuid16();
}
#endif

#ifdef __NR_getgid16
static asmlinkage long custom_getgid16(void)
{
    asmlinkage long (*org_getgid16)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getgid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getgid16 = (asmlinkage long (*)(void)) org_sys_table[__NR_getgid16];
    return org_getgid16();
}
#endif

#ifdef __NR_getegid16
static asmlinkage long custom_getegid16(void)
{
    asmlinkage long (*org_getegid16)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getegid16,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getegid16 = (asmlinkage long (*)(void)) org_sys_table[__NR_getegid16];
    return org_getegid16();
}
#endif

#endif

#ifdef __NR_utime
static asmlinkage long custom_utime(char __user *filename, struct utimbuf __user *times)
{
    asmlinkage long (*org_utime)(char __user *filename, struct utimbuf __user *times);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:utime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_utime = (asmlinkage long (*)(char __user *filename, struct utimbuf __user *times)) org_sys_table[__NR_utime];
    return org_utime(filename, times);
}
#endif

#ifdef __NR_utimes
static asmlinkage long custom_utimes(char __user *filename, struct timeval __user *utimes)
{
    asmlinkage long (*org_utimes)(char __user *filename, struct timeval __user *utimes);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:utimes,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_utimes = (asmlinkage long (*)(char __user *filename, struct timeval __user *utimes)) org_sys_table[__NR_utimes];
    return org_utimes(filename, utimes);
}
#endif

#ifdef __NR_lseek
static asmlinkage long custom_lseek(unsigned int fd, off_t offset, unsigned int whence)
{
    asmlinkage long (*org_lseek)(unsigned int fd, off_t offset, unsigned int whence);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lseek,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lseek = (asmlinkage long (*)(unsigned int fd, off_t offset, unsigned int whence)) org_sys_table[__NR_lseek];
    return org_lseek(fd, offset, whence);
}
#endif

#ifdef __NR_llseek
static asmlinkage long custom_llseek(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence)
{
    asmlinkage long (*org_llseek)(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:llseek,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_llseek = (asmlinkage long (*)(unsigned int fd, unsigned long offset_high, unsigned long offset_low, loff_t __user *result, unsigned int whence)) org_sys_table[__NR_llseek];
    return org_llseek(fd, offset_high, offset_low, result, whence);
}
#endif

#ifdef __NR_read
static asmlinkage long custom_read(unsigned int fd, char __user *buf, size_t count)
{
    asmlinkage long (*org_read)(unsigned int fd, char __user *buf, size_t count);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:read,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_read = (asmlinkage long (*)(unsigned int fd, char __user *buf, size_t count)) org_sys_table[__NR_read];
    return org_read(fd, buf, count);
}
#endif

#ifdef __NR_readahead
static asmlinkage long custom_readahead(int fd, loff_t offset, size_t count)
{
    asmlinkage long (*org_readahead)(int fd, loff_t offset, size_t count);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:readahead,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_readahead = (asmlinkage long (*)(int fd, loff_t offset, size_t count)) org_sys_table[__NR_readahead];
    return org_readahead(fd, offset, count);
}
#endif

#ifdef __NR_readv
static asmlinkage long custom_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
    asmlinkage long (*org_readv)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:readv,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_readv = (asmlinkage long (*)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)) org_sys_table[__NR_readv];
    return org_readv(fd, vec, vlen);
}
#endif

#ifdef __NR_write
static asmlinkage long custom_write(unsigned int fd, const char __user *buf, size_t count)
{
    asmlinkage long (*org_write)(unsigned int fd, const char __user *buf, size_t count);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:write,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_write = (asmlinkage long (*)(unsigned int fd, const char __user *buf, size_t count)) org_sys_table[__NR_write];
    return org_write(fd, buf, count);
}
#endif

#ifdef __NR_writev
static asmlinkage long custom_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
{
    asmlinkage long (*org_writev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:writev,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_writev = (asmlinkage long (*)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)) org_sys_table[__NR_writev];
    return org_writev(fd, vec, vlen);
}
#endif

#ifdef __NR_pread64
static asmlinkage long custom_pread64(unsigned int fd, char __user *buf, size_t count, loff_t pos)
{
    asmlinkage long (*org_pread64)(unsigned int fd, char __user *buf, size_t count, loff_t pos);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pread64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pread64 = (asmlinkage long (*)(unsigned int fd, char __user *buf, size_t count, loff_t pos)) org_sys_table[__NR_pread64];
    return org_pread64(fd, buf, count, pos);
}
#endif

#ifdef __NR_pwrite64
static asmlinkage long custom_pwrite64(unsigned int fd, const char __user *buf, size_t count, loff_t pos)
{
    asmlinkage long (*org_pwrite64)(unsigned int fd, const char __user *buf, size_t count, loff_t pos);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pwrite64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pwrite64 = (asmlinkage long (*)(unsigned int fd, const char __user *buf, size_t count, loff_t pos)) org_sys_table[__NR_pwrite64];
    return org_pwrite64(fd, buf, count, pos);
}
#endif

#ifdef __NR_preadv
static asmlinkage long custom_preadv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
    asmlinkage long (*org_preadv)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:preadv,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_preadv = (asmlinkage long (*)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h)) org_sys_table[__NR_preadv];
    return org_preadv(fd, vec, vlen, pos_l, pos_h);
}
#endif

#ifdef __NR_preadv2
static asmlinkage long custom_preadv2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags)
{
    asmlinkage long (*org_preadv2)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:preadv2,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_preadv2 = (asmlinkage long (*)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags)) org_sys_table[__NR_preadv2];
    return org_preadv2(fd, vec, vlen, pos_l, pos_h, flags);
}
#endif

#ifdef __NR_pwritev
static asmlinkage long custom_pwritev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
    asmlinkage long (*org_pwritev)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pwritev,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pwritev = (asmlinkage long (*)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h)) org_sys_table[__NR_pwritev];
    return org_pwritev(fd, vec, vlen, pos_l, pos_h);
}
#endif

#ifdef __NR_pwritev2
static asmlinkage long custom_pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags)
{
    asmlinkage long (*org_pwritev2)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pwritev2,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pwritev2 = (asmlinkage long (*)(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, rwf_t flags)) org_sys_table[__NR_pwritev2];
    return org_pwritev2(fd, vec, vlen, pos_l, pos_h, flags);
}
#endif

#ifdef __NR_getcwd
static asmlinkage long custom_getcwd(char __user *buf, unsigned long size)
{
    asmlinkage long (*org_getcwd)(char __user *buf, unsigned long size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getcwd,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getcwd = (asmlinkage long (*)(char __user *buf, unsigned long size)) org_sys_table[__NR_getcwd];
    return org_getcwd(buf, size);
}
#endif

#ifdef __NR_mkdir
static asmlinkage long custom_mkdir(const char __user *pathname, umode_t mode)
{
    asmlinkage long (*org_mkdir)(const char __user *pathname, umode_t mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mkdir,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mkdir = (asmlinkage long (*)(const char __user *pathname, umode_t mode)) org_sys_table[__NR_mkdir];
    return org_mkdir(pathname, mode);
}
#endif

#ifdef __NR_chdir
static asmlinkage long custom_chdir(const char __user *filename)
{
    asmlinkage long (*org_chdir)(const char __user *filename);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:chdir,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_chdir = (asmlinkage long (*)(const char __user *filename)) org_sys_table[__NR_chdir];
    return org_chdir(filename);
}
#endif

#ifdef __NR_fchdir
static asmlinkage long custom_fchdir(unsigned int fd)
{
    asmlinkage long (*org_fchdir)(unsigned int fd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fchdir,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fchdir = (asmlinkage long (*)(unsigned int fd)) org_sys_table[__NR_fchdir];
    return org_fchdir(fd);
}
#endif

#ifdef __NR_rmdir
static asmlinkage long custom_rmdir(const char __user *pathname)
{
    asmlinkage long (*org_rmdir)(const char __user *pathname);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:rmdir,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_rmdir = (asmlinkage long (*)(const char __user *pathname)) org_sys_table[__NR_rmdir];
    return org_rmdir(pathname);
}
#endif

#ifdef __NR_lookup_dcookie
static asmlinkage long custom_lookup_dcookie(u64 cookie64, char __user *buf, size_t len)
{
    asmlinkage long (*org_lookup_dcookie)(u64 cookie64, char __user *buf, size_t len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:lookup_dcookie,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_lookup_dcookie = (asmlinkage long (*)(u64 cookie64, char __user *buf, size_t len)) org_sys_table[__NR_lookup_dcookie];
    return org_lookup_dcookie(cookie64, buf, len);
}
#endif

#ifdef __NR_quotactl
static asmlinkage long custom_quotactl(unsigned int cmd, const char __user *special, qid_t id, void __user *addr)
{
    asmlinkage long (*org_quotactl)(unsigned int cmd, const char __user *special, qid_t id, void __user *addr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:quotactl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_quotactl = (asmlinkage long (*)(unsigned int cmd, const char __user *special, qid_t id, void __user *addr)) org_sys_table[__NR_quotactl];
    return org_quotactl(cmd, special, id, addr);
}
#endif

#ifdef __NR_getdents
static asmlinkage long custom_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)
{
    asmlinkage long (*org_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getdents,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getdents = (asmlinkage long (*)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count)) org_sys_table[__NR_getdents];
    return org_getdents(fd, dirent, count);
}
#endif

#ifdef __NR_getdents64
static asmlinkage long custom_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)
{
    asmlinkage long (*org_getdents64)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getdents64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getdents64 = (asmlinkage long (*)(unsigned int fd, struct linux_dirent64 __user *dirent, unsigned int count)) org_sys_table[__NR_getdents64];
    return org_getdents64(fd, dirent, count);
}
#endif


#ifdef __NR_setsockopt
static asmlinkage long custom_setsockopt(int fd, int level, int optname, char __user *optval, int optlen)
{
    asmlinkage long (*org_setsockopt)(int fd, int level, int optname, char __user *optval, int optlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setsockopt,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setsockopt = (asmlinkage long (*)(int fd, int level, int optname, char __user *optval, int optlen)) org_sys_table[__NR_setsockopt];
    return org_setsockopt(fd, level, optname, optval, optlen);
}
#endif

#ifdef __NR_getsockopt
static asmlinkage long custom_getsockopt(int fd, int level, int optname, char __user *optval, int __user *optlen)
{
    asmlinkage long (*org_getsockopt)(int fd, int level, int optname, char __user *optval, int __user *optlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getsockopt,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getsockopt = (asmlinkage long (*)(int fd, int level, int optname, char __user *optval, int __user *optlen)) org_sys_table[__NR_getsockopt];
    return org_getsockopt(fd, level, optname, optval, optlen);
}
#endif

#ifdef __NR_bind
static asmlinkage long custom_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
    asmlinkage long (*org_bind)(int fd, struct sockaddr __user *umyaddr, int addrlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:bind,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_bind = (asmlinkage long (*)(int fd, struct sockaddr __user *umyaddr, int addrlen)) org_sys_table[__NR_bind];
    return org_bind(fd, umyaddr, addrlen);
}
#endif

#ifdef __NR_connect
static asmlinkage long custom_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
    asmlinkage long (*org_connect)(int fd, struct sockaddr __user *uservaddr, int addrlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:connect,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_connect = (asmlinkage long (*)(int fd, struct sockaddr __user *uservaddr, int addrlen)) org_sys_table[__NR_connect];
    return org_connect(fd, uservaddr, addrlen);
}
#endif

#ifdef __NR_accept
static asmlinkage long custom_accept(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)
{
    asmlinkage long (*org_accept)(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:accept,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_accept = (asmlinkage long (*)(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen)) org_sys_table[__NR_accept];
    return org_accept(fd, upeer_sockaddr, upeer_addrlen);
}
#endif

#ifdef __NR_accept4
static asmlinkage long custom_accept4(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)
{
    asmlinkage long (*org_accept4)(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:accept4,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_accept4 = (asmlinkage long (*)(int fd, struct sockaddr __user *upeer_sockaddr, int __user *upeer_addrlen, int flags)) org_sys_table[__NR_accept4];
    return org_accept4(fd, upeer_sockaddr, upeer_addrlen, flags);
}
#endif

#ifdef __NR_getsockname
static asmlinkage long custom_getsockname(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
    asmlinkage long (*org_getsockname)(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getsockname,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getsockname = (asmlinkage long (*)(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)) org_sys_table[__NR_getsockname];
    return org_getsockname(fd, usockaddr, usockaddr_len);
}
#endif

#ifdef __NR_getpeername
static asmlinkage long custom_getpeername(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)
{
    asmlinkage long (*org_getpeername)(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getpeername,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getpeername = (asmlinkage long (*)(int fd, struct sockaddr __user *usockaddr, int __user *usockaddr_len)) org_sys_table[__NR_getpeername];
    return org_getpeername(fd, usockaddr, usockaddr_len);
}
#endif

#ifdef __NR_send
static asmlinkage long custom_send(int fd, void __user *buff, size_t len, unsigned int flags)
{
    asmlinkage long (*org_send)(int fd, void __user *buff, size_t len, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:send,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_send = (asmlinkage long (*)(int fd, void __user *buff, size_t len, unsigned int flags)) org_sys_table[__NR_send];
    return org_send(fd, buff, len, flags);
}
#endif

#ifdef __NR_sendto
static asmlinkage long custom_sendto(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)
{
    asmlinkage long (*org_sendto)(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sendto,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sendto = (asmlinkage long (*)(int fd, void __user *buff, size_t len, unsigned int flags, struct sockaddr __user *addr, int addr_len)) org_sys_table[__NR_sendto];
    return org_sendto(fd, buff, len, flags, addr, addr_len);
}
#endif

#ifdef __NR_sendmsg
static asmlinkage long custom_sendmsg(int fd, struct user_msghdr __user *msg, unsigned flags)
{
    asmlinkage long (*org_sendmsg)(int fd, struct user_msghdr __user *msg, unsigned flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sendmsg,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sendmsg = (asmlinkage long (*)(int fd, struct user_msghdr __user *msg, unsigned flags)) org_sys_table[__NR_sendmsg];
    return org_sendmsg(fd, msg, flags);
}
#endif

#ifdef __NR_sendmmsg
static asmlinkage long custom_sendmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags)
{
    asmlinkage long (*org_sendmmsg)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sendmmsg,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sendmmsg = (asmlinkage long (*)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags)) org_sys_table[__NR_sendmmsg];
    return org_sendmmsg(fd, msg, vlen, flags);
}
#endif

#ifdef __NR_recv
static asmlinkage long custom_recv(int fd, void __user *ubuf, size_t size, unsigned int flags)
{
    asmlinkage long (*org_recv)(int fd, void __user *ubuf, size_t size, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:recv,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_recv = (asmlinkage long (*)(int fd, void __user *ubuf, size_t size, unsigned int flags)) org_sys_table[__NR_recv];
    return org_recv(fd, ubuf, size, flags);
}
#endif

#ifdef __NR_recvfrom
static asmlinkage long custom_recvfrom(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)
{
    asmlinkage long (*org_recvfrom)(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:recvfrom,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_recvfrom = (asmlinkage long (*)(int fd, void __user *ubuf, size_t size, unsigned int flags, struct sockaddr __user *addr, int __user *addr_len)) org_sys_table[__NR_recvfrom];
    return org_recvfrom(fd, ubuf, size, flags, addr, addr_len);
}
#endif

#ifdef __NR_recvmsg
static asmlinkage long custom_recvmsg(int fd, struct user_msghdr __user *msg, unsigned flags)
{
    asmlinkage long (*org_recvmsg)(int fd, struct user_msghdr __user *msg, unsigned flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:recvmsg,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_recvmsg = (asmlinkage long (*)(int fd, struct user_msghdr __user *msg, unsigned flags)) org_sys_table[__NR_recvmsg];
    return org_recvmsg(fd, msg, flags);
}
#endif

#ifdef __NR_recvmmsg
static asmlinkage long custom_recvmmsg(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout)
{
    asmlinkage long (*org_recvmmsg)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:recvmmsg,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_recvmmsg = (asmlinkage long (*)(int fd, struct mmsghdr __user *msg, unsigned int vlen, unsigned flags, struct timespec __user *timeout)) org_sys_table[__NR_recvmmsg];
    return org_recvmmsg(fd, msg, vlen, flags, timeout);
}
#endif

#ifdef __NR_socket
static asmlinkage long custom_socket(int family, int type, int protocol)
{
    asmlinkage long (*org_socket)(int family, int type, int protocol);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:socket,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_socket = (asmlinkage long (*)(int family, int type, int protocol)) org_sys_table[__NR_socket];
    return org_socket(family, type, protocol);
}
#endif

#ifdef __NR_socketpair
static asmlinkage long custom_socketpair(int family, int type, int protocol, int __user *usockvec)
{
    asmlinkage long (*org_socketpair)(int family, int type, int protocol, int __user *usockvec);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:socketpair,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_socketpair = (asmlinkage long (*)(int family, int type, int protocol, int __user *usockvec)) org_sys_table[__NR_socketpair];
    return org_socketpair(family, type, protocol, usockvec);
}
#endif

#ifdef __NR_socketcall
static asmlinkage long custom_socketcall(int call, unsigned long __user *args)
{
    asmlinkage long (*org_socketcall)(int call, unsigned long __user *args);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:socketcall,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_socketcall = (asmlinkage long (*)(int call, unsigned long __user *args)) org_sys_table[__NR_socketcall];
    return org_socketcall(call, args);
}
#endif

#ifdef __NR_listen
static asmlinkage long custom_listen(int fd, int backlog)
{
    asmlinkage long (*org_listen)(int fd, int backlog);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:listen,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_listen = (asmlinkage long (*)(int fd, int backlog)) org_sys_table[__NR_listen];
    return org_listen(fd, backlog);
}
#endif

#ifdef __NR_poll
static asmlinkage long custom_poll(struct pollfd __user *ufds, unsigned int nfds, int timeout)
{
    asmlinkage long (*org_poll)(struct pollfd __user *ufds, unsigned int nfds, int timeout);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:poll,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_poll = (asmlinkage long (*)(struct pollfd __user *ufds, unsigned int nfds, int timeout)) org_sys_table[__NR_poll];
    return org_poll(ufds, nfds, timeout);
}
#endif

#ifdef __NR_select
static asmlinkage long custom_select(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)
{
    asmlinkage long (*org_select)(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:select,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_select = (asmlinkage long (*)(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timeval __user *tvp)) org_sys_table[__NR_select];
    return org_select(n, inp, outp, exp, tvp);
}
#endif

#ifdef __NR_old_select
static asmlinkage long custom_old_select(struct sel_arg_struct __user *arg)
{
    asmlinkage long (*org_old_select)(struct sel_arg_struct __user *arg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:old_select,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_old_select = (asmlinkage long (*)(struct sel_arg_struct __user *arg)) org_sys_table[__NR_old_select];
    return org_old_select(arg);
}
#endif

#ifdef __NR_epoll_create
static asmlinkage long custom_epoll_create(int size)
{
    asmlinkage long (*org_epoll_create)(int size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:epoll_create,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_epoll_create = (asmlinkage long (*)(int size)) org_sys_table[__NR_epoll_create];
    return org_epoll_create(size);
}
#endif

#ifdef __NR_epoll_create1
static asmlinkage long custom_epoll_create1(int flags)
{
    asmlinkage long (*org_epoll_create1)(int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:epoll_create1,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_epoll_create1 = (asmlinkage long (*)(int flags)) org_sys_table[__NR_epoll_create1];
    return org_epoll_create1(flags);
}
#endif

#ifdef __NR_epoll_ctl
static asmlinkage long custom_epoll_ctl(int epfd, int op, int fd, struct epoll_event __user *event)
{
    asmlinkage long (*org_epoll_ctl)(int epfd, int op, int fd, struct epoll_event __user *event);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:epoll_ctl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_epoll_ctl = (asmlinkage long (*)(int epfd, int op, int fd, struct epoll_event __user *event)) org_sys_table[__NR_epoll_ctl];
    return org_epoll_ctl(epfd, op, fd, event);
}
#endif

#ifdef __NR_epoll_wait
static asmlinkage long custom_epoll_wait(int epfd, struct epoll_event __user *events, int maxevents, int timeout)
{
    asmlinkage long (*org_epoll_wait)(int epfd, struct epoll_event __user *events, int maxevents, int timeout);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:epoll_wait,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_epoll_wait = (asmlinkage long (*)(int epfd, struct epoll_event __user *events, int maxevents, int timeout)) org_sys_table[__NR_epoll_wait];
    return org_epoll_wait(epfd, events, maxevents, timeout);
}
#endif

#ifdef __NR_epoll_pwait
static asmlinkage long custom_epoll_pwait(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)
{
    asmlinkage long (*org_epoll_pwait)(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:epoll_pwait,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_epoll_pwait = (asmlinkage long (*)(int epfd, struct epoll_event __user *events, int maxevents, int timeout, const sigset_t __user *sigmask, size_t sigsetsize)) org_sys_table[__NR_epoll_pwait];
    return org_epoll_pwait(epfd, events, maxevents, timeout, sigmask, sigsetsize);
}
#endif

#ifdef __NR_gethostname
static asmlinkage long custom_gethostname(char __user *name, int len)
{
    asmlinkage long (*org_gethostname)(char __user *name, int len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:gethostname,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_gethostname = (asmlinkage long (*)(char __user *name, int len)) org_sys_table[__NR_gethostname];
    return org_gethostname(name, len);
}
#endif

#ifdef __NR_sethostname
static asmlinkage long custom_sethostname(char __user *name, int len)
{
    asmlinkage long (*org_sethostname)(char __user *name, int len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sethostname,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sethostname = (asmlinkage long (*)(char __user *name, int len)) org_sys_table[__NR_sethostname];
    return org_sethostname(name, len);
}
#endif

#ifdef __NR_setdomainname
static asmlinkage long custom_setdomainname(char __user *name, int len)
{
    asmlinkage long (*org_setdomainname)(char __user *name, int len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setdomainname,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setdomainname = (asmlinkage long (*)(char __user *name, int len)) org_sys_table[__NR_setdomainname];
    return org_setdomainname(name, len);
}
#endif

#ifdef __NR_newuname
static asmlinkage long custom_newuname(struct new_utsname __user *name)
{
    asmlinkage long (*org_newuname)(struct new_utsname __user *name);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:newuname,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_newuname = (asmlinkage long (*)(struct new_utsname __user *name)) org_sys_table[__NR_newuname];
    return org_newuname(name);
}
#endif

#ifdef __NR_uname
static asmlinkage long custom_uname(struct old_utsname __user *ubuf)
{
    asmlinkage long (*org_uname)(struct old_utsname __user *ubuf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:uname,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_uname = (asmlinkage long (*)(struct old_utsname __user *ubuf)) org_sys_table[__NR_uname];
    return org_uname(ubuf);
}
#endif

#ifdef __NR_olduname
static asmlinkage long custom_olduname(struct oldold_utsname __user *)
{
    asmlinkage long (*org_olduname)(struct oldold_utsname __user *);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:olduname,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_olduname = (asmlinkage long (*)(struct oldold_utsname __user *)) org_sys_table[__NR_olduname];
}
#endif


#ifdef __NR_getrlimit
static asmlinkage long custom_getrlimit(unsigned int resource, struct rlimit __user *rlim)
{
    asmlinkage long (*org_getrlimit)(unsigned int resource, struct rlimit __user *rlim);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getrlimit,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getrlimit = (asmlinkage long (*)(unsigned int resource, struct rlimit __user *rlim)) org_sys_table[__NR_getrlimit];
    return org_getrlimit(resource, rlim);
}
#endif

#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT
#ifdef __NR_old_getrlimit
static asmlinkage long custom_old_getrlimit(unsigned int resource, struct rlimit __user *rlim)
{
    asmlinkage long (*org_old_getrlimit)(unsigned int resource, struct rlimit __user *rlim);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:old_getrlimit,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_old_getrlimit = (asmlinkage long (*)(unsigned int resource, struct rlimit __user *rlim)) org_sys_table[__NR_old_getrlimit];
    return org_old_getrlimit(resource, rlim);
}
#endif

#endif
#ifdef __NR_setrlimit
static asmlinkage long custom_setrlimit(unsigned int resource, struct rlimit __user *rlim)
{
    asmlinkage long (*org_setrlimit)(unsigned int resource, struct rlimit __user *rlim);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setrlimit,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setrlimit = (asmlinkage long (*)(unsigned int resource, struct rlimit __user *rlim)) org_sys_table[__NR_setrlimit];
    return org_setrlimit(resource, rlim);
}
#endif

#ifdef __NR_prlimit64
static asmlinkage long custom_prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim)
{
    asmlinkage long (*org_prlimit64)(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:prlimit64,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_prlimit64 = (asmlinkage long (*)(pid_t pid, unsigned int resource, const struct rlimit64 __user *new_rlim, struct rlimit64 __user *old_rlim)) org_sys_table[__NR_prlimit64];
    return org_prlimit64(pid, resource, new_rlim, old_rlim);
}
#endif

#ifdef __NR_getrusage
static asmlinkage long custom_getrusage(int who, struct rusage __user *ru)
{
    asmlinkage long (*org_getrusage)(int who, struct rusage __user *ru);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getrusage,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getrusage = (asmlinkage long (*)(int who, struct rusage __user *ru)) org_sys_table[__NR_getrusage];
    return org_getrusage(who, ru);
}
#endif

#ifdef __NR_umask
static asmlinkage long custom_umask(int mask)
{
    asmlinkage long (*org_umask)(int mask);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:umask,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_umask = (asmlinkage long (*)(int mask)) org_sys_table[__NR_umask];
    return org_umask(mask);
}
#endif


#ifdef __NR_msgget
static asmlinkage long custom_msgget(key_t key, int msgflg)
{
    asmlinkage long (*org_msgget)(key_t key, int msgflg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:msgget,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_msgget = (asmlinkage long (*)(key_t key, int msgflg)) org_sys_table[__NR_msgget];
    return org_msgget(key, msgflg);
}
#endif

#ifdef __NR_msgsnd
static asmlinkage long custom_msgsnd(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg)
{
    asmlinkage long (*org_msgsnd)(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:msgsnd,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_msgsnd = (asmlinkage long (*)(int msqid, struct msgbuf __user *msgp, size_t msgsz, int msgflg)) org_sys_table[__NR_msgsnd];
    return org_msgsnd(msqid, msgp, msgsz, msgflg);
}
#endif

#ifdef __NR_msgrcv
static asmlinkage long custom_msgrcv(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg)
{
    asmlinkage long (*org_msgrcv)(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:msgrcv,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_msgrcv = (asmlinkage long (*)(int msqid, struct msgbuf __user *msgp, size_t msgsz, long msgtyp, int msgflg)) org_sys_table[__NR_msgrcv];
    return org_msgrcv(msqid, msgp, msgsz, msgtyp, msgflg);
}
#endif

#ifdef __NR_msgctl
static asmlinkage long custom_msgctl(int msqid, int cmd, struct msqid_ds __user *buf)
{
    asmlinkage long (*org_msgctl)(int msqid, int cmd, struct msqid_ds __user *buf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:msgctl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_msgctl = (asmlinkage long (*)(int msqid, int cmd, struct msqid_ds __user *buf)) org_sys_table[__NR_msgctl];
    return org_msgctl(msqid, cmd, buf);
}
#endif


#ifdef __NR_semget
static asmlinkage long custom_semget(key_t key, int nsems, int semflg)
{
    asmlinkage long (*org_semget)(key_t key, int nsems, int semflg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:semget,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_semget = (asmlinkage long (*)(key_t key, int nsems, int semflg)) org_sys_table[__NR_semget];
    return org_semget(key, nsems, semflg);
}
#endif

#ifdef __NR_semop
static asmlinkage long custom_semop(int semid, struct sembuf __user *sops, unsigned nsops)
{
    asmlinkage long (*org_semop)(int semid, struct sembuf __user *sops, unsigned nsops);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:semop,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_semop = (asmlinkage long (*)(int semid, struct sembuf __user *sops, unsigned nsops)) org_sys_table[__NR_semop];
    return org_semop(semid, sops, nsops);
}
#endif

#ifdef __NR_semctl
static asmlinkage long custom_semctl(int semid, int semnum, int cmd, unsigned long arg)
{
    asmlinkage long (*org_semctl)(int semid, int semnum, int cmd, unsigned long arg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:semctl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_semctl = (asmlinkage long (*)(int semid, int semnum, int cmd, unsigned long arg)) org_sys_table[__NR_semctl];
    return org_semctl(semid, semnum, cmd, arg);
}
#endif

#ifdef __NR_semtimedop
static asmlinkage long custom_semtimedop(int semid, struct sembuf __user *sops, unsigned nsops, const struct timespec __user *timeout)
{
    asmlinkage long (*org_semtimedop)(int semid, struct sembuf __user *sops, unsigned nsops, const struct timespec __user *timeout);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:semtimedop,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_semtimedop = (asmlinkage long (*)(int semid, struct sembuf __user *sops, unsigned nsops, const struct timespec __user *timeout)) org_sys_table[__NR_semtimedop];
    return org_semtimedop(semid, sops, nsops, timeout);
}
#endif

#ifdef __NR_shmat
static asmlinkage long custom_shmat(int shmid, char __user *shmaddr, int shmflg)
{
    asmlinkage long (*org_shmat)(int shmid, char __user *shmaddr, int shmflg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:shmat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_shmat = (asmlinkage long (*)(int shmid, char __user *shmaddr, int shmflg)) org_sys_table[__NR_shmat];
    return org_shmat(shmid, shmaddr, shmflg);
}
#endif

#ifdef __NR_shmget
static asmlinkage long custom_shmget(key_t key, size_t size, int flag)
{
    asmlinkage long (*org_shmget)(key_t key, size_t size, int flag);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:shmget,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_shmget = (asmlinkage long (*)(key_t key, size_t size, int flag)) org_sys_table[__NR_shmget];
    return org_shmget(key, size, flag);
}
#endif

#ifdef __NR_shmdt
static asmlinkage long custom_shmdt(char __user *shmaddr)
{
    asmlinkage long (*org_shmdt)(char __user *shmaddr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:shmdt,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_shmdt = (asmlinkage long (*)(char __user *shmaddr)) org_sys_table[__NR_shmdt];
    return org_shmdt(shmaddr);
}
#endif

#ifdef __NR_shmctl
static asmlinkage long custom_shmctl(int shmid, int cmd, struct shmid_ds __user *buf)
{
    asmlinkage long (*org_shmctl)(int shmid, int cmd, struct shmid_ds __user *buf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:shmctl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_shmctl = (asmlinkage long (*)(int shmid, int cmd, struct shmid_ds __user *buf)) org_sys_table[__NR_shmctl];
    return org_shmctl(shmid, cmd, buf);
}
#endif

#ifdef __NR_ipc
static asmlinkage long custom_ipc(unsigned int call, int first, unsigned long second, unsigned long third, void __user *ptr, long fifth)
{
    asmlinkage long (*org_ipc)(unsigned int call, int first, unsigned long second, unsigned long third, void __user *ptr, long fifth);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ipc,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ipc = (asmlinkage long (*)(unsigned int call, int first, unsigned long second, unsigned long third, void __user *ptr, long fifth)) org_sys_table[__NR_ipc];
    return org_ipc(call, first, second, third, ptr, fifth);
}
#endif


#ifdef __NR_mq_open
static asmlinkage long custom_mq_open(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr)
{
    asmlinkage long (*org_mq_open)(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mq_open,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mq_open = (asmlinkage long (*)(const char __user *name, int oflag, umode_t mode, struct mq_attr __user *attr)) org_sys_table[__NR_mq_open];
    return org_mq_open(name, oflag, mode, attr);
}
#endif

#ifdef __NR_mq_unlink
static asmlinkage long custom_mq_unlink(const char __user *name)
{
    asmlinkage long (*org_mq_unlink)(const char __user *name);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mq_unlink,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mq_unlink = (asmlinkage long (*)(const char __user *name)) org_sys_table[__NR_mq_unlink];
    return org_mq_unlink(name);
}
#endif

#ifdef __NR_mq_timedsend
static asmlinkage long custom_mq_timedsend(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout)
{
    asmlinkage long (*org_mq_timedsend)(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mq_timedsend,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mq_timedsend = (asmlinkage long (*)(mqd_t mqdes, const char __user *msg_ptr, size_t msg_len, unsigned int msg_prio, const struct timespec __user *abs_timeout)) org_sys_table[__NR_mq_timedsend];
    return org_mq_timedsend(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
}
#endif

#ifdef __NR_mq_timedreceive
static asmlinkage long custom_mq_timedreceive(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout)
{
    asmlinkage long (*org_mq_timedreceive)(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mq_timedreceive,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mq_timedreceive = (asmlinkage long (*)(mqd_t mqdes, char __user *msg_ptr, size_t msg_len, unsigned int __user *msg_prio, const struct timespec __user *abs_timeout)) org_sys_table[__NR_mq_timedreceive];
    return org_mq_timedreceive(mqdes, msg_ptr, msg_len, msg_prio, abs_timeout);
}
#endif

#ifdef __NR_mq_notify
static asmlinkage long custom_mq_notify(mqd_t mqdes, const struct sigevent __user *notification)
{
    asmlinkage long (*org_mq_notify)(mqd_t mqdes, const struct sigevent __user *notification);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mq_notify,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mq_notify = (asmlinkage long (*)(mqd_t mqdes, const struct sigevent __user *notification)) org_sys_table[__NR_mq_notify];
    return org_mq_notify(mqdes, notification);
}
#endif

#ifdef __NR_mq_getsetattr
static asmlinkage long custom_mq_getsetattr(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat)
{
    asmlinkage long (*org_mq_getsetattr)(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mq_getsetattr,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mq_getsetattr = (asmlinkage long (*)(mqd_t mqdes, const struct mq_attr __user *mqstat, struct mq_attr __user *omqstat)) org_sys_table[__NR_mq_getsetattr];
    return org_mq_getsetattr(mqdes, mqstat, omqstat);
}
#endif


#ifdef __NR_pciconfig_iobase
static asmlinkage long custom_pciconfig_iobase(long which, unsigned long bus, unsigned long devfn)
{
    asmlinkage long (*org_pciconfig_iobase)(long which, unsigned long bus, unsigned long devfn);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pciconfig_iobase,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pciconfig_iobase = (asmlinkage long (*)(long which, unsigned long bus, unsigned long devfn)) org_sys_table[__NR_pciconfig_iobase];
    return org_pciconfig_iobase(which, bus, devfn);
}
#endif

#ifdef __NR_pciconfig_read
static asmlinkage long custom_pciconfig_read(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf)
{
    asmlinkage long (*org_pciconfig_read)(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pciconfig_read,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pciconfig_read = (asmlinkage long (*)(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf)) org_sys_table[__NR_pciconfig_read];
    return org_pciconfig_read(bus, dfn, off, len, buf);
}
#endif

#ifdef __NR_pciconfig_write
static asmlinkage long custom_pciconfig_write(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf)
{
    asmlinkage long (*org_pciconfig_write)(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pciconfig_write,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pciconfig_write = (asmlinkage long (*)(unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len, void __user *buf)) org_sys_table[__NR_pciconfig_write];
    return org_pciconfig_write(bus, dfn, off, len, buf);
}
#endif


#ifdef __NR_prctl
static asmlinkage long custom_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    asmlinkage long (*org_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:prctl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_prctl = (asmlinkage long (*)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)) org_sys_table[__NR_prctl];
    return org_prctl(option, arg2, arg3, arg4, arg5);
}
#endif

#ifdef __NR_swapon
static asmlinkage long custom_swapon(const char __user *specialfile, int swap_flags)
{
    asmlinkage long (*org_swapon)(const char __user *specialfile, int swap_flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:swapon,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_swapon = (asmlinkage long (*)(const char __user *specialfile, int swap_flags)) org_sys_table[__NR_swapon];
    return org_swapon(specialfile, swap_flags);
}
#endif

#ifdef __NR_swapoff
static asmlinkage long custom_swapoff(const char __user *specialfile)
{
    asmlinkage long (*org_swapoff)(const char __user *specialfile);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:swapoff,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_swapoff = (asmlinkage long (*)(const char __user *specialfile)) org_sys_table[__NR_swapoff];
    return org_swapoff(specialfile);
}
#endif

#ifdef __NR_sysctl
static asmlinkage long custom_sysctl(struct __sysctl_args __user *args)
{
    asmlinkage long (*org_sysctl)(struct __sysctl_args __user *args);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sysctl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sysctl = (asmlinkage long (*)(struct __sysctl_args __user *args)) org_sys_table[__NR_sysctl];
    return org_sysctl(args);
}
#endif

#ifdef __NR_sysinfo
static asmlinkage long custom_sysinfo(struct sysinfo __user *info)
{
    asmlinkage long (*org_sysinfo)(struct sysinfo __user *info);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sysinfo,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sysinfo = (asmlinkage long (*)(struct sysinfo __user *info)) org_sys_table[__NR_sysinfo];
    return org_sysinfo(info);
}
#endif

#ifdef __NR_sysfs
static asmlinkage long custom_sysfs(int option, unsigned long arg1, unsigned long arg2)
{
    asmlinkage long (*org_sysfs)(int option, unsigned long arg1, unsigned long arg2);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sysfs,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sysfs = (asmlinkage long (*)(int option, unsigned long arg1, unsigned long arg2)) org_sys_table[__NR_sysfs];
    return org_sysfs(option, arg1, arg2);
}
#endif

#ifdef __NR_syslog
static asmlinkage long custom_syslog(int type, char __user *buf, int len)
{
    asmlinkage long (*org_syslog)(int type, char __user *buf, int len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:syslog,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_syslog = (asmlinkage long (*)(int type, char __user *buf, int len)) org_sys_table[__NR_syslog];
    return org_syslog(type, buf, len);
}
#endif

#ifdef __NR_uselib
static asmlinkage long custom_uselib(const char __user *library)
{
    asmlinkage long (*org_uselib)(const char __user *library);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:uselib,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_uselib = (asmlinkage long (*)(const char __user *library)) org_sys_table[__NR_uselib];
    return org_uselib(library);
}
#endif

#ifdef __NR_ni_syscall
static asmlinkage long custom_ni_syscall(void)
{
    asmlinkage long (*org_ni_syscall)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ni_syscall,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ni_syscall = (asmlinkage long (*)(void)) org_sys_table[__NR_ni_syscall];
    return org_ni_syscall();
}
#endif

#ifdef __NR_ptrace
static asmlinkage long custom_ptrace(long request, long pid, unsigned long addr, unsigned long data)
{
    asmlinkage long (*org_ptrace)(long request, long pid, unsigned long addr, unsigned long data);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ptrace,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ptrace = (asmlinkage long (*)(long request, long pid, unsigned long addr, unsigned long data)) org_sys_table[__NR_ptrace];
    return org_ptrace(request, pid, addr, data);
}
#endif


#ifdef __NR_add_key
static asmlinkage long custom_add_key(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid)
{
    asmlinkage long (*org_add_key)(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:add_key,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_add_key = (asmlinkage long (*)(const char __user *_type, const char __user *_description, const void __user *_payload, size_t plen, key_serial_t destringid)) org_sys_table[__NR_add_key];
    return org_add_key(_type, _description, _payload, plen, destringid);
}
#endif


#ifdef __NR_request_key
static asmlinkage long custom_request_key(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid)
{
    asmlinkage long (*org_request_key)(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:request_key,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_request_key = (asmlinkage long (*)(const char __user *_type, const char __user *_description, const char __user *_callout_info, key_serial_t destringid)) org_sys_table[__NR_request_key];
    return org_request_key(_type, _description, _callout_info, destringid);
}
#endif


#ifdef __NR_keyctl
static asmlinkage long custom_keyctl(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    asmlinkage long (*org_keyctl)(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:keyctl,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_keyctl = (asmlinkage long (*)(int cmd, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)) org_sys_table[__NR_keyctl];
    return org_keyctl(cmd, arg2, arg3, arg4, arg5);
}
#endif


#ifdef __NR_ioprio_set
static asmlinkage long custom_ioprio_set(int which, int who, int ioprio)
{
    asmlinkage long (*org_ioprio_set)(int which, int who, int ioprio);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ioprio_set,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ioprio_set = (asmlinkage long (*)(int which, int who, int ioprio)) org_sys_table[__NR_ioprio_set];
    return org_ioprio_set(which, who, ioprio);
}
#endif

#ifdef __NR_ioprio_get
static asmlinkage long custom_ioprio_get(int which, int who)
{
    asmlinkage long (*org_ioprio_get)(int which, int who);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ioprio_get,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ioprio_get = (asmlinkage long (*)(int which, int who)) org_sys_table[__NR_ioprio_get];
    return org_ioprio_get(which, who);
}
#endif

#ifdef __NR_set_mempolicy
static asmlinkage long custom_set_mempolicy(int mode, const unsigned long __user *nmask, unsigned long maxnode)
{
    asmlinkage long (*org_set_mempolicy)(int mode, const unsigned long __user *nmask, unsigned long maxnode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:set_mempolicy,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_set_mempolicy = (asmlinkage long (*)(int mode, const unsigned long __user *nmask, unsigned long maxnode)) org_sys_table[__NR_set_mempolicy];
    return org_set_mempolicy(mode, nmask, maxnode);
}
#endif

#ifdef __NR_migrate_pages
static asmlinkage long custom_migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to)
{
    asmlinkage long (*org_migrate_pages)(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:migrate_pages,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_migrate_pages = (asmlinkage long (*)(pid_t pid, unsigned long maxnode, const unsigned long __user *from, const unsigned long __user *to)) org_sys_table[__NR_migrate_pages];
    return org_migrate_pages(pid, maxnode, from, to);
}
#endif

#ifdef __NR_move_pages
static asmlinkage long custom_move_pages(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags)
{
    asmlinkage long (*org_move_pages)(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:move_pages,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_move_pages = (asmlinkage long (*)(pid_t pid, unsigned long nr_pages, const void __user * __user *pages, const int __user *nodes, int __user *status, int flags)) org_sys_table[__NR_move_pages];
    return org_move_pages(pid, nr_pages, pages, nodes, status, flags);
}
#endif

#ifdef __NR_mbind
static asmlinkage long custom_mbind(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user *nmask, unsigned long maxnode, unsigned flags)
{
    asmlinkage long (*org_mbind)(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user *nmask, unsigned long maxnode, unsigned flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mbind,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mbind = (asmlinkage long (*)(unsigned long start, unsigned long len, unsigned long mode, const unsigned long __user *nmask, unsigned long maxnode, unsigned flags)) org_sys_table[__NR_mbind];
    return org_mbind(start, len, mode, nmask, maxnode, flags);
}
#endif

#ifdef __NR_get_mempolicy
static asmlinkage long custom_get_mempolicy(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)
{
    asmlinkage long (*org_get_mempolicy)(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:get_mempolicy,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_get_mempolicy = (asmlinkage long (*)(int __user *policy, unsigned long __user *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)) org_sys_table[__NR_get_mempolicy];
    return org_get_mempolicy(policy, nmask, maxnode, addr, flags);
}
#endif


#ifdef __NR_inotify_init
static asmlinkage long custom_inotify_init(void)
{
    asmlinkage long (*org_inotify_init)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:inotify_init,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_inotify_init = (asmlinkage long (*)(void)) org_sys_table[__NR_inotify_init];
    return org_inotify_init();
}
#endif

#ifdef __NR_inotify_init1
static asmlinkage long custom_inotify_init1(int flags)
{
    asmlinkage long (*org_inotify_init1)(int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:inotify_init1,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_inotify_init1 = (asmlinkage long (*)(int flags)) org_sys_table[__NR_inotify_init1];
    return org_inotify_init1(flags);
}
#endif

#ifdef __NR_inotify_add_watch
static asmlinkage long custom_inotify_add_watch(int fd, const char __user *path, u32 mask)
{
    asmlinkage long (*org_inotify_add_watch)(int fd, const char __user *path, u32 mask);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:inotify_add_watch,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_inotify_add_watch = (asmlinkage long (*)(int fd, const char __user *path, u32 mask)) org_sys_table[__NR_inotify_add_watch];
    return org_inotify_add_watch(fd, path, mask);
}
#endif

#ifdef __NR_inotify_rm_watch
static asmlinkage long custom_inotify_rm_watch(int fd, __s32 wd)
{
    asmlinkage long (*org_inotify_rm_watch)(int fd, __s32 wd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:inotify_rm_watch,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_inotify_rm_watch = (asmlinkage long (*)(int fd, __s32 wd)) org_sys_table[__NR_inotify_rm_watch];
    return org_inotify_rm_watch(fd, wd);
}
#endif


#ifdef __NR_spu_run
static asmlinkage long custom_spu_run(int fd, __u32 __user *unpc, __u32 __user *ustatus)
{
    asmlinkage long (*org_spu_run)(int fd, __u32 __user *unpc, __u32 __user *ustatus);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:spu_run,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_spu_run = (asmlinkage long (*)(int fd, __u32 __user *unpc, __u32 __user *ustatus)) org_sys_table[__NR_spu_run];
    return org_spu_run(fd, unpc, ustatus);
}
#endif

#ifdef __NR_spu_create
static asmlinkage long custom_spu_create(const char __user *name, unsigned int flags, umode_t mode, int fd)
{
    asmlinkage long (*org_spu_create)(const char __user *name, unsigned int flags, umode_t mode, int fd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:spu_create,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_spu_create = (asmlinkage long (*)(const char __user *name, unsigned int flags, umode_t mode, int fd)) org_sys_table[__NR_spu_create];
    return org_spu_create(name, flags, mode, fd);
}
#endif


#ifdef __NR_mknodat
static asmlinkage long custom_mknodat(int dfd, const char __user * filename, umode_t mode, unsigned dev)
{
    asmlinkage long (*org_mknodat)(int dfd, const char __user * filename, umode_t mode, unsigned dev);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mknodat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mknodat = (asmlinkage long (*)(int dfd, const char __user * filename, umode_t mode, unsigned dev)) org_sys_table[__NR_mknodat];
    return org_mknodat(dfd, filename, mode, dev);
}
#endif

#ifdef __NR_mkdirat
static asmlinkage long custom_mkdirat(int dfd, const char __user * pathname, umode_t mode)
{
    asmlinkage long (*org_mkdirat)(int dfd, const char __user * pathname, umode_t mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mkdirat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mkdirat = (asmlinkage long (*)(int dfd, const char __user * pathname, umode_t mode)) org_sys_table[__NR_mkdirat];
    return org_mkdirat(dfd, pathname, mode);
}
#endif

#ifdef __NR_unlinkat
static asmlinkage long custom_unlinkat(int dfd, const char __user * pathname, int flag)
{
    asmlinkage long (*org_unlinkat)(int dfd, const char __user * pathname, int flag);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:unlinkat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_unlinkat = (asmlinkage long (*)(int dfd, const char __user * pathname, int flag)) org_sys_table[__NR_unlinkat];
    return org_unlinkat(dfd, pathname, flag);
}
#endif

#ifdef __NR_symlinkat
static asmlinkage long custom_symlinkat(const char __user * oldname, int newdfd, const char __user * newname)
{
    asmlinkage long (*org_symlinkat)(const char __user * oldname, int newdfd, const char __user * newname);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:symlinkat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_symlinkat = (asmlinkage long (*)(const char __user * oldname, int newdfd, const char __user * newname)) org_sys_table[__NR_symlinkat];
    return org_symlinkat(oldname, newdfd, newname);
}
#endif

#ifdef __NR_linkat
static asmlinkage long custom_linkat(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags)
{
    asmlinkage long (*org_linkat)(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:linkat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_linkat = (asmlinkage long (*)(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags)) org_sys_table[__NR_linkat];
    return org_linkat(olddfd, oldname, newdfd, newname, flags);
}
#endif

#ifdef __NR_renameat
static asmlinkage long custom_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname)
{
    asmlinkage long (*org_renameat)(int olddfd, const char __user * oldname, int newdfd, const char __user * newname);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:renameat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_renameat = (asmlinkage long (*)(int olddfd, const char __user * oldname, int newdfd, const char __user * newname)) org_sys_table[__NR_renameat];
    return org_renameat(olddfd, oldname, newdfd, newname);
}
#endif

#ifdef __NR_renameat2
static asmlinkage long custom_renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags)
{
    asmlinkage long (*org_renameat2)(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:renameat2,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_renameat2 = (asmlinkage long (*)(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags)) org_sys_table[__NR_renameat2];
    return org_renameat2(olddfd, oldname, newdfd, newname, flags);
}
#endif

#ifdef __NR_futimesat
static asmlinkage long custom_futimesat(int dfd, const char __user *filename, struct timeval __user *utimes)
{
    asmlinkage long (*org_futimesat)(int dfd, const char __user *filename, struct timeval __user *utimes);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:futimesat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_futimesat = (asmlinkage long (*)(int dfd, const char __user *filename, struct timeval __user *utimes)) org_sys_table[__NR_futimesat];
    return org_futimesat(dfd, filename, utimes);
}
#endif

#ifdef __NR_faccessat
static asmlinkage long custom_faccessat(int dfd, const char __user *filename, int mode)
{
    asmlinkage long (*org_faccessat)(int dfd, const char __user *filename, int mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:faccessat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_faccessat = (asmlinkage long (*)(int dfd, const char __user *filename, int mode)) org_sys_table[__NR_faccessat];
    return org_faccessat(dfd, filename, mode);
}
#endif

#ifdef __NR_fchmodat
static asmlinkage long custom_fchmodat(int dfd, const char __user * filename, umode_t mode)
{
    asmlinkage long (*org_fchmodat)(int dfd, const char __user * filename, umode_t mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fchmodat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fchmodat = (asmlinkage long (*)(int dfd, const char __user * filename, umode_t mode)) org_sys_table[__NR_fchmodat];
    return org_fchmodat(dfd, filename, mode);
}
#endif

#ifdef __NR_fchownat
static asmlinkage long custom_fchownat(int dfd, const char __user *filename, uid_t user, gid_t group, int flag)
{
    asmlinkage long (*org_fchownat)(int dfd, const char __user *filename, uid_t user, gid_t group, int flag);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fchownat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fchownat = (asmlinkage long (*)(int dfd, const char __user *filename, uid_t user, gid_t group, int flag)) org_sys_table[__NR_fchownat];
    return org_fchownat(dfd, filename, user, group, flag);
}
#endif

#ifdef __NR_openat
static asmlinkage long custom_openat(int dfd, const char __user *filename, int flags, umode_t mode)
{
    asmlinkage long (*org_openat)(int dfd, const char __user *filename, int flags, umode_t mode);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:openat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_openat = (asmlinkage long (*)(int dfd, const char __user *filename, int flags, umode_t mode)) org_sys_table[__NR_openat];
    return org_openat(dfd, filename, flags, mode);
}
#endif

#ifdef __NR_newfstatat
static asmlinkage long custom_newfstatat(int dfd, const char __user *filename, struct stat __user *statbuf, int flag)
{
    asmlinkage long (*org_newfstatat)(int dfd, const char __user *filename, struct stat __user *statbuf, int flag);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:newfstatat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_newfstatat = (asmlinkage long (*)(int dfd, const char __user *filename, struct stat __user *statbuf, int flag)) org_sys_table[__NR_newfstatat];
    return org_newfstatat(dfd, filename, statbuf, flag);
}
#endif

#ifdef __NR_readlinkat
static asmlinkage long custom_readlinkat(int dfd, const char __user *path, char __user *buf, int bufsiz)
{
    asmlinkage long (*org_readlinkat)(int dfd, const char __user *path, char __user *buf, int bufsiz);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:readlinkat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_readlinkat = (asmlinkage long (*)(int dfd, const char __user *path, char __user *buf, int bufsiz)) org_sys_table[__NR_readlinkat];
    return org_readlinkat(dfd, path, buf, bufsiz);
}
#endif

#ifdef __NR_utimensat
static asmlinkage long custom_utimensat(int dfd, const char __user *filename, struct timespec __user *utimes, int flags)
{
    asmlinkage long (*org_utimensat)(int dfd, const char __user *filename, struct timespec __user *utimes, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:utimensat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_utimensat = (asmlinkage long (*)(int dfd, const char __user *filename, struct timespec __user *utimes, int flags)) org_sys_table[__NR_utimensat];
    return org_utimensat(dfd, filename, utimes, flags);
}
#endif

#ifdef __NR_unshare
static asmlinkage long custom_unshare(unsigned long unshare_flags)
{
    asmlinkage long (*org_unshare)(unsigned long unshare_flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:unshare,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_unshare = (asmlinkage long (*)(unsigned long unshare_flags)) org_sys_table[__NR_unshare];
    return org_unshare(unshare_flags);
}
#endif


#ifdef __NR_splice
static asmlinkage long custom_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)
{
    asmlinkage long (*org_splice)(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:splice,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_splice = (asmlinkage long (*)(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)) org_sys_table[__NR_splice];
    return org_splice(fd_in, off_in, fd_out, off_out, len, flags);
}
#endif


#ifdef __NR_vmsplice
static asmlinkage long custom_vmsplice(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags)
{
    asmlinkage long (*org_vmsplice)(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:vmsplice,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_vmsplice = (asmlinkage long (*)(int fd, const struct iovec __user *iov, unsigned long nr_segs, unsigned int flags)) org_sys_table[__NR_vmsplice];
    return org_vmsplice(fd, iov, nr_segs, flags);
}
#endif


#ifdef __NR_tee
static asmlinkage long custom_tee(int fdin, int fdout, size_t len, unsigned int flags)
{
    asmlinkage long (*org_tee)(int fdin, int fdout, size_t len, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:tee,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_tee = (asmlinkage long (*)(int fdin, int fdout, size_t len, unsigned int flags)) org_sys_table[__NR_tee];
    return org_tee(fdin, fdout, len, flags);
}
#endif


#ifdef __NR_sync_file_range
static asmlinkage long custom_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
{
    asmlinkage long (*org_sync_file_range)(int fd, loff_t offset, loff_t nbytes, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sync_file_range,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sync_file_range = (asmlinkage long (*)(int fd, loff_t offset, loff_t nbytes, unsigned int flags)) org_sys_table[__NR_sync_file_range];
    return org_sync_file_range(fd, offset, nbytes, flags);
}
#endif

#ifdef __NR_sync_file_range2
static asmlinkage long custom_sync_file_range2(int fd, unsigned int flags, loff_t offset, loff_t nbytes)
{
    asmlinkage long (*org_sync_file_range2)(int fd, unsigned int flags, loff_t offset, loff_t nbytes);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:sync_file_range2,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_sync_file_range2 = (asmlinkage long (*)(int fd, unsigned int flags, loff_t offset, loff_t nbytes)) org_sys_table[__NR_sync_file_range2];
    return org_sync_file_range2(fd, flags, offset, nbytes);
}
#endif

#ifdef __NR_get_robust_list
static asmlinkage long custom_get_robust_list(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr)
{
    asmlinkage long (*org_get_robust_list)(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:get_robust_list,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_get_robust_list = (asmlinkage long (*)(int pid, struct robust_list_head __user * __user *head_ptr, size_t __user *len_ptr)) org_sys_table[__NR_get_robust_list];
    return org_get_robust_list(pid, head_ptr, len_ptr);
}
#endif

#ifdef __NR_set_robust_list
static asmlinkage long custom_set_robust_list(struct robust_list_head __user *head, size_t len)
{
    asmlinkage long (*org_set_robust_list)(struct robust_list_head __user *head, size_t len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:set_robust_list,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_set_robust_list = (asmlinkage long (*)(struct robust_list_head __user *head, size_t len)) org_sys_table[__NR_set_robust_list];
    return org_set_robust_list(head, len);
}
#endif

#ifdef __NR_getcpu
static asmlinkage long custom_getcpu(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache)
{
    asmlinkage long (*org_getcpu)(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getcpu,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getcpu = (asmlinkage long (*)(unsigned __user *cpu, unsigned __user *node, struct getcpu_cache __user *cache)) org_sys_table[__NR_getcpu];
    return org_getcpu(cpu, node, cache);
}
#endif

#ifdef __NR_signalfd
static asmlinkage long custom_signalfd(int ufd, sigset_t __user *user_mask, size_t sizemask)
{
    asmlinkage long (*org_signalfd)(int ufd, sigset_t __user *user_mask, size_t sizemask);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:signalfd,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_signalfd = (asmlinkage long (*)(int ufd, sigset_t __user *user_mask, size_t sizemask)) org_sys_table[__NR_signalfd];
    return org_signalfd(ufd, user_mask, sizemask);
}
#endif

#ifdef __NR_signalfd4
static asmlinkage long custom_signalfd4(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags)
{
    asmlinkage long (*org_signalfd4)(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:signalfd4,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_signalfd4 = (asmlinkage long (*)(int ufd, sigset_t __user *user_mask, size_t sizemask, int flags)) org_sys_table[__NR_signalfd4];
    return org_signalfd4(ufd, user_mask, sizemask, flags);
}
#endif

#ifdef __NR_timerfd_create
static asmlinkage long custom_timerfd_create(int clockid, int flags)
{
    asmlinkage long (*org_timerfd_create)(int clockid, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:timerfd_create,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_timerfd_create = (asmlinkage long (*)(int clockid, int flags)) org_sys_table[__NR_timerfd_create];
    return org_timerfd_create(clockid, flags);
}
#endif

#ifdef __NR_timerfd_settime
static asmlinkage long custom_timerfd_settime(int ufd, int flags, const struct itimerspec __user *utmr, struct itimerspec __user *otmr)
{
    asmlinkage long (*org_timerfd_settime)(int ufd, int flags, const struct itimerspec __user *utmr, struct itimerspec __user *otmr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:timerfd_settime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_timerfd_settime = (asmlinkage long (*)(int ufd, int flags, const struct itimerspec __user *utmr, struct itimerspec __user *otmr)) org_sys_table[__NR_timerfd_settime];
    return org_timerfd_settime(ufd, flags, utmr, otmr);
}
#endif

#ifdef __NR_timerfd_gettime
static asmlinkage long custom_timerfd_gettime(int ufd, struct itimerspec __user *otmr)
{
    asmlinkage long (*org_timerfd_gettime)(int ufd, struct itimerspec __user *otmr);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:timerfd_gettime,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_timerfd_gettime = (asmlinkage long (*)(int ufd, struct itimerspec __user *otmr)) org_sys_table[__NR_timerfd_gettime];
    return org_timerfd_gettime(ufd, otmr);
}
#endif

#ifdef __NR_eventfd
static asmlinkage long custom_eventfd(unsigned int count)
{
    asmlinkage long (*org_eventfd)(unsigned int count);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:eventfd,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_eventfd = (asmlinkage long (*)(unsigned int count)) org_sys_table[__NR_eventfd];
    return org_eventfd(count);
}
#endif

#ifdef __NR_eventfd2
static asmlinkage long custom_eventfd2(unsigned int count, int flags)
{
    asmlinkage long (*org_eventfd2)(unsigned int count, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:eventfd2,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_eventfd2 = (asmlinkage long (*)(unsigned int count, int flags)) org_sys_table[__NR_eventfd2];
    return org_eventfd2(count, flags);
}
#endif

#ifdef __NR_memfd_create
static asmlinkage long custom_memfd_create(const char __user *uname_ptr, unsigned int flags)
{
    asmlinkage long (*org_memfd_create)(const char __user *uname_ptr, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:memfd_create,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_memfd_create = (asmlinkage long (*)(const char __user *uname_ptr, unsigned int flags)) org_sys_table[__NR_memfd_create];
    return org_memfd_create(uname_ptr, flags);
}
#endif

#ifdef __NR_userfaultfd
static asmlinkage long custom_userfaultfd(int flags)
{
    asmlinkage long (*org_userfaultfd)(int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:userfaultfd,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_userfaultfd = (asmlinkage long (*)(int flags)) org_sys_table[__NR_userfaultfd];
    return org_userfaultfd(flags);
}
#endif

#ifdef __NR_fallocate
static asmlinkage long custom_fallocate(int fd, int mode, loff_t offset, loff_t len)
{
    asmlinkage long (*org_fallocate)(int fd, int mode, loff_t offset, loff_t len);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fallocate,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fallocate = (asmlinkage long (*)(int fd, int mode, loff_t offset, loff_t len)) org_sys_table[__NR_fallocate];
    return org_fallocate(fd, mode, offset, len);
}
#endif

#ifdef __NR_old_readdir
static asmlinkage long custom_old_readdir(unsigned int, struct old_linux_dirent __user *, unsigned int)
{
    asmlinkage long (*org_old_readdir)(unsigned int, struct old_linux_dirent __user *, unsigned int);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:old_readdir,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_old_readdir = (asmlinkage long (*)(unsigned int, struct old_linux_dirent __user *, unsigned int)) org_sys_table[__NR_old_readdir];
}
#endif

#ifdef __NR_pselect6
static asmlinkage long custom_pselect6(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig)
{
    asmlinkage long (*org_pselect6)(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pselect6,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pselect6 = (asmlinkage long (*)(int n, fd_set __user *inp, fd_set __user *outp, fd_set __user *exp, struct timespec __user *tsp, void __user *sig)) org_sys_table[__NR_pselect6];
    return org_pselect6(n, inp, outp, exp, tsp, sig);
}
#endif

#ifdef __NR_ppoll
static asmlinkage long custom_ppoll(struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize)
{
    asmlinkage long (*org_ppoll)(struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:ppoll,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_ppoll = (asmlinkage long (*)(struct pollfd __user *ufds, unsigned int nfds, struct timespec __user *tsp, const sigset_t __user *sigmask, size_t sigsetsize)) org_sys_table[__NR_ppoll];
    return org_ppoll(ufds, nfds, tsp, sigmask, sigsetsize);
}
#endif

#ifdef __NR_fanotify_init
static asmlinkage long custom_fanotify_init(unsigned int flags, unsigned int event_f_flags)
{
    asmlinkage long (*org_fanotify_init)(unsigned int flags, unsigned int event_f_flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fanotify_init,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fanotify_init = (asmlinkage long (*)(unsigned int flags, unsigned int event_f_flags)) org_sys_table[__NR_fanotify_init];
    return org_fanotify_init(flags, event_f_flags);
}
#endif

#ifdef __NR_fanotify_mark
static asmlinkage long custom_fanotify_mark(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char  __user *pathname)
{
    asmlinkage long (*org_fanotify_mark)(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char  __user *pathname);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fanotify_mark,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fanotify_mark = (asmlinkage long (*)(int fanotify_fd, unsigned int flags, u64 mask, int fd, const char  __user *pathname)) org_sys_table[__NR_fanotify_mark];
    return org_fanotify_mark(fanotify_fd, flags, mask, fd, pathname);
}
#endif

#ifdef __NR_syncfs
static asmlinkage long custom_syncfs(int fd)
{
    asmlinkage long (*org_syncfs)(int fd);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:syncfs,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_syncfs = (asmlinkage long (*)(int fd)) org_sys_table[__NR_syncfs];
    return org_syncfs(fd);
}
#endif


#ifdef __NR_fork
static asmlinkage long custom_fork(void)
{
    asmlinkage long (*org_fork)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:fork,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_fork = (asmlinkage long (*)(void)) org_sys_table[__NR_fork];
    return org_fork();
}
#endif

#ifdef __NR_vfork
static asmlinkage long custom_vfork(void)
{
    asmlinkage long (*org_vfork)(void);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:vfork,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_vfork = (asmlinkage long (*)(void)) org_sys_table[__NR_vfork];
    return org_vfork();
}
#endif

#ifdef CONFIG_CLONE_BACKWARDS
#ifdef __NR_clone
static asmlinkage long custom_clone(unsigned long, unsigned long, int __user *, unsigned long, int __user *)
{
    asmlinkage long (*org_clone)(unsigned long, unsigned long, int __user *, unsigned long, int __user *);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:clone,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_clone = (asmlinkage long (*)(unsigned long, unsigned long, int __user *, unsigned long, int __user *)) org_sys_table[__NR_clone];
}
#endif

#else
#ifdef CONFIG_CLONE_BACKWARDS3
#ifdef __NR_clone
static asmlinkage long custom_clone(unsigned long, unsigned long, int, int __user *, int __user *, unsigned long)
{
    asmlinkage long (*org_clone)(unsigned long, unsigned long, int, int __user *, int __user *, unsigned long);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:clone,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_clone = (asmlinkage long (*)(unsigned long, unsigned long, int, int __user *, int __user *, unsigned long)) org_sys_table[__NR_clone];
}
#endif

#else
#ifdef __NR_clone
static asmlinkage long custom_clone(unsigned long clone_flags, unsigned long newsp, int __user *parent_tid, int __user *child_tid, unsigned long tls)
{
    asmlinkage long (*org_clone)(unsigned long clone_flags, unsigned long newsp, int __user *parent_tid, int __user *child_tid, unsigned long tls);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:clone,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_clone = (asmlinkage long (*)(unsigned long clone_flags, unsigned long newsp, int __user *parent_tid, int __user *child_tid, unsigned long tls)) org_sys_table[__NR_clone];
    return org_clone(clone_flags, newsp, parent_tid, child_tid, tls);
}
#endif

#endif
#endif

#ifdef __NR_execve
static asmlinkage long custom_execve(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp)
{
    asmlinkage long (*org_execve)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:execve,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_execve = (asmlinkage long (*)(const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp)) org_sys_table[__NR_execve];
    return org_execve(filename, argv, envp);
}
#endif


#ifdef __NR_perf_event_open
static asmlinkage long custom_perf_event_open(struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    asmlinkage long (*org_perf_event_open)(struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:perf_event_open,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_perf_event_open = (asmlinkage long (*)(struct perf_event_attr __user *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags)) org_sys_table[__NR_perf_event_open];
    return org_perf_event_open(attr_uptr, pid, cpu, group_fd, flags);
}
#endif


#ifdef __NR_mmap_pgoff
static asmlinkage long custom_mmap_pgoff(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)
{
    asmlinkage long (*org_mmap_pgoff)(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mmap_pgoff,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mmap_pgoff = (asmlinkage long (*)(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long pgoff)) org_sys_table[__NR_mmap_pgoff];
    return org_mmap_pgoff(addr, len, prot, flags, fd, pgoff);
}
#endif

#ifdef __NR_old_mmap
static asmlinkage long custom_old_mmap(struct mmap_arg_struct __user *arg)
{
    asmlinkage long (*org_old_mmap)(struct mmap_arg_struct __user *arg);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:old_mmap,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_old_mmap = (asmlinkage long (*)(struct mmap_arg_struct __user *arg)) org_sys_table[__NR_old_mmap];
    return org_old_mmap(arg);
}
#endif

#ifdef __NR_name_to_handle_at
static asmlinkage long custom_name_to_handle_at(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag)
{
    asmlinkage long (*org_name_to_handle_at)(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:name_to_handle_at,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_name_to_handle_at = (asmlinkage long (*)(int dfd, const char __user *name, struct file_handle __user *handle, int __user *mnt_id, int flag)) org_sys_table[__NR_name_to_handle_at];
    return org_name_to_handle_at(dfd, name, handle, mnt_id, flag);
}
#endif

#ifdef __NR_open_by_handle_at
static asmlinkage long custom_open_by_handle_at(int mountdirfd, struct file_handle __user *handle, int flags)
{
    asmlinkage long (*org_open_by_handle_at)(int mountdirfd, struct file_handle __user *handle, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:open_by_handle_at,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_open_by_handle_at = (asmlinkage long (*)(int mountdirfd, struct file_handle __user *handle, int flags)) org_sys_table[__NR_open_by_handle_at];
    return org_open_by_handle_at(mountdirfd, handle, flags);
}
#endif

#ifdef __NR_setns
static asmlinkage long custom_setns(int fd, int nstype)
{
    asmlinkage long (*org_setns)(int fd, int nstype);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:setns,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_setns = (asmlinkage long (*)(int fd, int nstype)) org_sys_table[__NR_setns];
    return org_setns(fd, nstype);
}
#endif

#ifdef __NR_process_vm_readv
static asmlinkage long custom_process_vm_readv(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
    asmlinkage long (*org_process_vm_readv)(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:process_vm_readv,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_process_vm_readv = (asmlinkage long (*)(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)) org_sys_table[__NR_process_vm_readv];
    return org_process_vm_readv(pid, lvec, liovcnt, rvec, riovcnt, flags);
}
#endif

#ifdef __NR_process_vm_writev
static asmlinkage long custom_process_vm_writev(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)
{
    asmlinkage long (*org_process_vm_writev)(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:process_vm_writev,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_process_vm_writev = (asmlinkage long (*)(pid_t pid, const struct iovec __user *lvec, unsigned long liovcnt, const struct iovec __user *rvec, unsigned long riovcnt, unsigned long flags)) org_sys_table[__NR_process_vm_writev];
    return org_process_vm_writev(pid, lvec, liovcnt, rvec, riovcnt, flags);
}
#endif


#ifdef __NR_kcmp
static asmlinkage long custom_kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2)
{
    asmlinkage long (*org_kcmp)(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:kcmp,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_kcmp = (asmlinkage long (*)(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2)) org_sys_table[__NR_kcmp];
    return org_kcmp(pid1, pid2, type, idx1, idx2);
}
#endif

#ifdef __NR_finit_module
static asmlinkage long custom_finit_module(int fd, const char __user *uargs, int flags)
{
    asmlinkage long (*org_finit_module)(int fd, const char __user *uargs, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:finit_module,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_finit_module = (asmlinkage long (*)(int fd, const char __user *uargs, int flags)) org_sys_table[__NR_finit_module];
    return org_finit_module(fd, uargs, flags);
}
#endif

#ifdef __NR_seccomp
static asmlinkage long custom_seccomp(unsigned int op, unsigned int flags, const char __user *uargs)
{
    asmlinkage long (*org_seccomp)(unsigned int op, unsigned int flags, const char __user *uargs);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:seccomp,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_seccomp = (asmlinkage long (*)(unsigned int op, unsigned int flags, const char __user *uargs)) org_sys_table[__NR_seccomp];
    return org_seccomp(op, flags, uargs);
}
#endif

#ifdef __NR_getrandom
static asmlinkage long custom_getrandom(char __user *buf, size_t count, unsigned int flags)
{
    asmlinkage long (*org_getrandom)(char __user *buf, size_t count, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:getrandom,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_getrandom = (asmlinkage long (*)(char __user *buf, size_t count, unsigned int flags)) org_sys_table[__NR_getrandom];
    return org_getrandom(buf, count, flags);
}
#endif

#ifdef __NR_bpf
static asmlinkage long custom_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    asmlinkage long (*org_bpf)(int cmd, union bpf_attr *attr, unsigned int size);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:bpf,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_bpf = (asmlinkage long (*)(int cmd, union bpf_attr *attr, unsigned int size)) org_sys_table[__NR_bpf];
    return org_bpf(cmd, attr, size);
}
#endif


#ifdef __NR_execveat
static asmlinkage long custom_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags)
{
    asmlinkage long (*org_execveat)(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:execveat,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_execveat = (asmlinkage long (*)(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags)) org_sys_table[__NR_execveat];
    return org_execveat(dfd, filename, argv, envp, flags);
}
#endif


#ifdef __NR_membarrier
static asmlinkage long custom_membarrier(int cmd, int flags)
{
    asmlinkage long (*org_membarrier)(int cmd, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:membarrier,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_membarrier = (asmlinkage long (*)(int cmd, int flags)) org_sys_table[__NR_membarrier];
    return org_membarrier(cmd, flags);
}
#endif

#ifdef __NR_copy_file_range
static asmlinkage long custom_copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)
{
    asmlinkage long (*org_copy_file_range)(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:copy_file_range,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_copy_file_range = (asmlinkage long (*)(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)) org_sys_table[__NR_copy_file_range];
    return org_copy_file_range(fd_in, off_in, fd_out, off_out, len, flags);
}
#endif


#ifdef __NR_mlock2
static asmlinkage long custom_mlock2(unsigned long start, size_t len, int flags)
{
    asmlinkage long (*org_mlock2)(unsigned long start, size_t len, int flags);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:mlock2,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_mlock2 = (asmlinkage long (*)(unsigned long start, size_t len, int flags)) org_sys_table[__NR_mlock2];
    return org_mlock2(start, len, flags);
}
#endif


#ifdef __NR_pkey_mprotect
static asmlinkage long custom_pkey_mprotect(unsigned long start, size_t len, unsigned long prot, int pkey)
{
    asmlinkage long (*org_pkey_mprotect)(unsigned long start, size_t len, unsigned long prot, int pkey);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pkey_mprotect,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pkey_mprotect = (asmlinkage long (*)(unsigned long start, size_t len, unsigned long prot, int pkey)) org_sys_table[__NR_pkey_mprotect];
    return org_pkey_mprotect(start, len, prot, pkey);
}
#endif

#ifdef __NR_pkey_alloc
static asmlinkage long custom_pkey_alloc(unsigned long flags, unsigned long init_val)
{
    asmlinkage long (*org_pkey_alloc)(unsigned long flags, unsigned long init_val);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pkey_alloc,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pkey_alloc = (asmlinkage long (*)(unsigned long flags, unsigned long init_val)) org_sys_table[__NR_pkey_alloc];
    return org_pkey_alloc(flags, init_val);
}
#endif

#ifdef __NR_pkey_free
static asmlinkage long custom_pkey_free(int pkey)
{
    asmlinkage long (*org_pkey_free)(int pkey);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:pkey_free,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_pkey_free = (asmlinkage long (*)(int pkey)) org_sys_table[__NR_pkey_free];
    return org_pkey_free(pkey);
}
#endif

#ifdef __NR_statx
static asmlinkage long custom_statx(int dfd, const char __user *path, unsigned flags, unsigned mask, struct statx __user *buffer)
{
    asmlinkage long (*org_statx)(int dfd, const char __user *path, unsigned flags, unsigned mask, struct statx __user *buffer);
    if(current->real_parent->pid == 12970)
    {
    	printk(KERN_WARNING "ISOLATES:statx,%s,%d,%d\n", current->comm, current->pid, current->cred->uid.val);
    }
    org_statx = (asmlinkage long (*)(int dfd, const char __user *path, unsigned flags, unsigned mask, struct statx __user *buffer)) org_sys_table[__NR_statx];
    return org_statx(dfd, path, flags, mask, buffer);
}
#endif


static int __init hello_init(void)
{
    
    printk(KERN_ALERT "ISOLATES:Custom FileOps module inserted successfully\n");
    
    sys_call_table = (sys_call_ptr_t *)kallsyms_lookup_name(sym_name);

// Remembering original system calls
    
#ifdef __NR_time
    org_sys_table[__NR_time] = sys_call_table[__NR_time];
#endif
#ifdef __NR_stime
    org_sys_table[__NR_stime] = sys_call_table[__NR_stime];
#endif
#ifdef __NR_gettimeofday
    org_sys_table[__NR_gettimeofday] = sys_call_table[__NR_gettimeofday];
#endif
#ifdef __NR_settimeofday
    org_sys_table[__NR_settimeofday] = sys_call_table[__NR_settimeofday];
#endif
#ifdef __NR_adjtimex
    org_sys_table[__NR_adjtimex] = sys_call_table[__NR_adjtimex];
#endif

#ifdef __NR_times
    org_sys_table[__NR_times] = sys_call_table[__NR_times];
#endif

#ifdef __NR_gettid
    org_sys_table[__NR_gettid] = sys_call_table[__NR_gettid];
#endif
#ifdef __NR_nanosleep
    org_sys_table[__NR_nanosleep] = sys_call_table[__NR_nanosleep];
#endif
#ifdef __NR_alarm
    org_sys_table[__NR_alarm] = sys_call_table[__NR_alarm];
#endif
#ifdef __NR_getpid
    org_sys_table[__NR_getpid] = sys_call_table[__NR_getpid];
#endif
#ifdef __NR_getppid
    org_sys_table[__NR_getppid] = sys_call_table[__NR_getppid];
#endif
#ifdef __NR_getuid
    org_sys_table[__NR_getuid] = sys_call_table[__NR_getuid];
#endif
#ifdef __NR_geteuid
    org_sys_table[__NR_geteuid] = sys_call_table[__NR_geteuid];
#endif
#ifdef __NR_getgid
    org_sys_table[__NR_getgid] = sys_call_table[__NR_getgid];
#endif
#ifdef __NR_getegid
    org_sys_table[__NR_getegid] = sys_call_table[__NR_getegid];
#endif
#ifdef __NR_getresuid
    org_sys_table[__NR_getresuid] = sys_call_table[__NR_getresuid];
#endif
#ifdef __NR_getresgid
    org_sys_table[__NR_getresgid] = sys_call_table[__NR_getresgid];
#endif
#ifdef __NR_getpgid
    org_sys_table[__NR_getpgid] = sys_call_table[__NR_getpgid];
#endif
#ifdef __NR_getpgrp
    org_sys_table[__NR_getpgrp] = sys_call_table[__NR_getpgrp];
#endif
#ifdef __NR_getsid
    org_sys_table[__NR_getsid] = sys_call_table[__NR_getsid];
#endif
#ifdef __NR_getgroups
    org_sys_table[__NR_getgroups] = sys_call_table[__NR_getgroups];
#endif

#ifdef __NR_setregid
    org_sys_table[__NR_setregid] = sys_call_table[__NR_setregid];
#endif
#ifdef __NR_setgid
    org_sys_table[__NR_setgid] = sys_call_table[__NR_setgid];
#endif
#ifdef __NR_setreuid
    org_sys_table[__NR_setreuid] = sys_call_table[__NR_setreuid];
#endif
#ifdef __NR_setuid
    org_sys_table[__NR_setuid] = sys_call_table[__NR_setuid];
#endif
#ifdef __NR_setresuid
    org_sys_table[__NR_setresuid] = sys_call_table[__NR_setresuid];
#endif
#ifdef __NR_setresgid
    org_sys_table[__NR_setresgid] = sys_call_table[__NR_setresgid];
#endif
#ifdef __NR_setfsuid
    org_sys_table[__NR_setfsuid] = sys_call_table[__NR_setfsuid];
#endif
#ifdef __NR_setfsgid
    org_sys_table[__NR_setfsgid] = sys_call_table[__NR_setfsgid];
#endif
#ifdef __NR_setpgid
    org_sys_table[__NR_setpgid] = sys_call_table[__NR_setpgid];
#endif
#ifdef __NR_setsid
    org_sys_table[__NR_setsid] = sys_call_table[__NR_setsid];
#endif
#ifdef __NR_setgroups
    org_sys_table[__NR_setgroups] = sys_call_table[__NR_setgroups];
#endif

#ifdef __NR_acct
    org_sys_table[__NR_acct] = sys_call_table[__NR_acct];
#endif
#ifdef __NR_capget
    org_sys_table[__NR_capget] = sys_call_table[__NR_capget];
#endif
#ifdef __NR_capset
    org_sys_table[__NR_capset] = sys_call_table[__NR_capset];
#endif
#ifdef __NR_personality
    org_sys_table[__NR_personality] = sys_call_table[__NR_personality];
#endif

#ifdef __NR_sigpending
    org_sys_table[__NR_sigpending] = sys_call_table[__NR_sigpending];
#endif
#ifdef __NR_sigprocmask
    org_sys_table[__NR_sigprocmask] = sys_call_table[__NR_sigprocmask];
#endif
#ifdef __NR_sigaltstack
    org_sys_table[__NR_sigaltstack] = sys_call_table[__NR_sigaltstack];
#endif

#ifdef __NR_getitimer
    org_sys_table[__NR_getitimer] = sys_call_table[__NR_getitimer];
#endif
#ifdef __NR_setitimer
    org_sys_table[__NR_setitimer] = sys_call_table[__NR_setitimer];
#endif
#ifdef __NR_timer_create
    org_sys_table[__NR_timer_create] = sys_call_table[__NR_timer_create];
#endif
#ifdef __NR_timer_gettime
    org_sys_table[__NR_timer_gettime] = sys_call_table[__NR_timer_gettime];
#endif
#ifdef __NR_timer_getoverrun
    org_sys_table[__NR_timer_getoverrun] = sys_call_table[__NR_timer_getoverrun];
#endif
#ifdef __NR_timer_settime
    org_sys_table[__NR_timer_settime] = sys_call_table[__NR_timer_settime];
#endif
#ifdef __NR_timer_delete
    org_sys_table[__NR_timer_delete] = sys_call_table[__NR_timer_delete];
#endif
#ifdef __NR_clock_settime
    org_sys_table[__NR_clock_settime] = sys_call_table[__NR_clock_settime];
#endif
#ifdef __NR_clock_gettime
    org_sys_table[__NR_clock_gettime] = sys_call_table[__NR_clock_gettime];
#endif
#ifdef __NR_clock_adjtime
    org_sys_table[__NR_clock_adjtime] = sys_call_table[__NR_clock_adjtime];
#endif
#ifdef __NR_clock_getres
    org_sys_table[__NR_clock_getres] = sys_call_table[__NR_clock_getres];
#endif
#ifdef __NR_clock_nanosleep
    org_sys_table[__NR_clock_nanosleep] = sys_call_table[__NR_clock_nanosleep];
#endif

#ifdef __NR_nice
    org_sys_table[__NR_nice] = sys_call_table[__NR_nice];
#endif
#ifdef __NR_sched_setscheduler
    org_sys_table[__NR_sched_setscheduler] = sys_call_table[__NR_sched_setscheduler];
#endif
#ifdef __NR_sched_setparam
    org_sys_table[__NR_sched_setparam] = sys_call_table[__NR_sched_setparam];
#endif
#ifdef __NR_sched_setattr
    org_sys_table[__NR_sched_setattr] = sys_call_table[__NR_sched_setattr];
#endif
#ifdef __NR_sched_getscheduler
    org_sys_table[__NR_sched_getscheduler] = sys_call_table[__NR_sched_getscheduler];
#endif
#ifdef __NR_sched_getparam
    org_sys_table[__NR_sched_getparam] = sys_call_table[__NR_sched_getparam];
#endif
#ifdef __NR_sched_getattr
    org_sys_table[__NR_sched_getattr] = sys_call_table[__NR_sched_getattr];
#endif
#ifdef __NR_sched_setaffinity
    org_sys_table[__NR_sched_setaffinity] = sys_call_table[__NR_sched_setaffinity];
#endif
#ifdef __NR_sched_getaffinity
    org_sys_table[__NR_sched_getaffinity] = sys_call_table[__NR_sched_getaffinity];
#endif
#ifdef __NR_sched_yield
    org_sys_table[__NR_sched_yield] = sys_call_table[__NR_sched_yield];
#endif
#ifdef __NR_sched_get_priority_max
    org_sys_table[__NR_sched_get_priority_max] = sys_call_table[__NR_sched_get_priority_max];
#endif
#ifdef __NR_sched_get_priority_min
    org_sys_table[__NR_sched_get_priority_min] = sys_call_table[__NR_sched_get_priority_min];
#endif
#ifdef __NR_sched_rr_get_interval
    org_sys_table[__NR_sched_rr_get_interval] = sys_call_table[__NR_sched_rr_get_interval];
#endif
#ifdef __NR_setpriority
    org_sys_table[__NR_setpriority] = sys_call_table[__NR_setpriority];
#endif
#ifdef __NR_getpriority
    org_sys_table[__NR_getpriority] = sys_call_table[__NR_getpriority];
#endif

#ifdef __NR_shutdown
    org_sys_table[__NR_shutdown] = sys_call_table[__NR_shutdown];
#endif
#ifdef __NR_reboot
    org_sys_table[__NR_reboot] = sys_call_table[__NR_reboot];
#endif
#ifdef __NR_restart_syscall
    org_sys_table[__NR_restart_syscall] = sys_call_table[__NR_restart_syscall];
#endif
#ifdef __NR_kexec_load
    org_sys_table[__NR_kexec_load] = sys_call_table[__NR_kexec_load];
#endif
#ifdef __NR_kexec_file_load
    org_sys_table[__NR_kexec_file_load] = sys_call_table[__NR_kexec_file_load];
#endif

#ifdef __NR_exit
    org_sys_table[__NR_exit] = sys_call_table[__NR_exit];
#endif
#ifdef __NR_exit_group
    org_sys_table[__NR_exit_group] = sys_call_table[__NR_exit_group];
#endif
#ifdef __NR_wait4
    org_sys_table[__NR_wait4] = sys_call_table[__NR_wait4];
#endif
#ifdef __NR_waitid
    org_sys_table[__NR_waitid] = sys_call_table[__NR_waitid];
#endif
#ifdef __NR_waitpid
    org_sys_table[__NR_waitpid] = sys_call_table[__NR_waitpid];
#endif
#ifdef __NR_set_tid_address
    org_sys_table[__NR_set_tid_address] = sys_call_table[__NR_set_tid_address];
#endif
#ifdef __NR_futex
    org_sys_table[__NR_futex] = sys_call_table[__NR_futex];
#endif

#ifdef __NR_init_module
    org_sys_table[__NR_init_module] = sys_call_table[__NR_init_module];
#endif
#ifdef __NR_delete_module
    org_sys_table[__NR_delete_module] = sys_call_table[__NR_delete_module];
#endif

#ifdef CONFIG_OLD_SIGSUSPEND
#ifdef __NR_sigsuspend
    org_sys_table[__NR_sigsuspend] = sys_call_table[__NR_sigsuspend];
#endif
#endif

#ifdef CONFIG_OLD_SIGSUSPEND3
#ifdef __NR_sigsuspend
    org_sys_table[__NR_sigsuspend] = sys_call_table[__NR_sigsuspend];
#endif
#endif

#ifdef __NR_rt_sigsuspend
    org_sys_table[__NR_rt_sigsuspend] = sys_call_table[__NR_rt_sigsuspend];
#endif

#ifdef CONFIG_OLD_SIGACTION
#ifdef __NR_sigaction
    org_sys_table[__NR_sigaction] = sys_call_table[__NR_sigaction];
#endif
#endif

#ifndef CONFIG_ODD_RT_SIGACTION
#ifdef __NR_rt_sigaction
    org_sys_table[__NR_rt_sigaction] = sys_call_table[__NR_rt_sigaction];
#endif
#endif
#ifdef __NR_rt_sigprocmask
    org_sys_table[__NR_rt_sigprocmask] = sys_call_table[__NR_rt_sigprocmask];
#endif
#ifdef __NR_rt_sigpending
    org_sys_table[__NR_rt_sigpending] = sys_call_table[__NR_rt_sigpending];
#endif
#ifdef __NR_rt_sigtimedwait
    org_sys_table[__NR_rt_sigtimedwait] = sys_call_table[__NR_rt_sigtimedwait];
#endif
#ifdef __NR_rt_tgsigqueueinfo
    org_sys_table[__NR_rt_tgsigqueueinfo] = sys_call_table[__NR_rt_tgsigqueueinfo];
#endif
#ifdef __NR_kill
    org_sys_table[__NR_kill] = sys_call_table[__NR_kill];
#endif
#ifdef __NR_tgkill
    org_sys_table[__NR_tgkill] = sys_call_table[__NR_tgkill];
#endif
#ifdef __NR_tkill
    org_sys_table[__NR_tkill] = sys_call_table[__NR_tkill];
#endif
#ifdef __NR_rt_sigqueueinfo
    org_sys_table[__NR_rt_sigqueueinfo] = sys_call_table[__NR_rt_sigqueueinfo];
#endif
#ifdef __NR_sgetmask
    org_sys_table[__NR_sgetmask] = sys_call_table[__NR_sgetmask];
#endif
#ifdef __NR_ssetmask
    org_sys_table[__NR_ssetmask] = sys_call_table[__NR_ssetmask];
#endif
#ifdef __NR_signal
    org_sys_table[__NR_signal] = sys_call_table[__NR_signal];
#endif
#ifdef __NR_pause
    org_sys_table[__NR_pause] = sys_call_table[__NR_pause];
#endif

#ifdef __NR_sync
    org_sys_table[__NR_sync] = sys_call_table[__NR_sync];
#endif
#ifdef __NR_fsync
    org_sys_table[__NR_fsync] = sys_call_table[__NR_fsync];
#endif
#ifdef __NR_fdatasync
    org_sys_table[__NR_fdatasync] = sys_call_table[__NR_fdatasync];
#endif
#ifdef __NR_bdflush
    org_sys_table[__NR_bdflush] = sys_call_table[__NR_bdflush];
#endif
#ifdef __NR_mount
    org_sys_table[__NR_mount] = sys_call_table[__NR_mount];
#endif
#ifdef __NR_umount
    org_sys_table[__NR_umount] = sys_call_table[__NR_umount];
#endif
#ifdef __NR_oldumount
    org_sys_table[__NR_oldumount] = sys_call_table[__NR_oldumount];
#endif
#ifdef __NR_truncate
    org_sys_table[__NR_truncate] = sys_call_table[__NR_truncate];
#endif
#ifdef __NR_ftruncate
    org_sys_table[__NR_ftruncate] = sys_call_table[__NR_ftruncate];
#endif
#ifdef __NR_stat
    org_sys_table[__NR_stat] = sys_call_table[__NR_stat];
#endif
#ifdef __NR_statfs
    org_sys_table[__NR_statfs] = sys_call_table[__NR_statfs];
#endif
#ifdef __NR_statfs64
    org_sys_table[__NR_statfs64] = sys_call_table[__NR_statfs64];
#endif
#ifdef __NR_fstatfs
    org_sys_table[__NR_fstatfs] = sys_call_table[__NR_fstatfs];
#endif
#ifdef __NR_fstatfs64
    org_sys_table[__NR_fstatfs64] = sys_call_table[__NR_fstatfs64];
#endif
#ifdef __NR_lstat
    org_sys_table[__NR_lstat] = sys_call_table[__NR_lstat];
#endif
#ifdef __NR_fstat
    org_sys_table[__NR_fstat] = sys_call_table[__NR_fstat];
#endif
#ifdef __NR_newstat
    org_sys_table[__NR_newstat] = sys_call_table[__NR_newstat];
#endif
#ifdef __NR_newlstat
    org_sys_table[__NR_newlstat] = sys_call_table[__NR_newlstat];
#endif
#ifdef __NR_newfstat
    org_sys_table[__NR_newfstat] = sys_call_table[__NR_newfstat];
#endif
#ifdef __NR_ustat
    org_sys_table[__NR_ustat] = sys_call_table[__NR_ustat];
#endif
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef __NR_stat64
    org_sys_table[__NR_stat64] = sys_call_table[__NR_stat64];
#endif
#ifdef __NR_fstat64
    org_sys_table[__NR_fstat64] = sys_call_table[__NR_fstat64];
#endif
#ifdef __NR_lstat64
    org_sys_table[__NR_lstat64] = sys_call_table[__NR_lstat64];
#endif
#ifdef __NR_fstatat64
    org_sys_table[__NR_fstatat64] = sys_call_table[__NR_fstatat64];
#endif
#endif
#if BITS_PER_LONG == 32
#ifdef __NR_truncate64
    org_sys_table[__NR_truncate64] = sys_call_table[__NR_truncate64];
#endif
#ifdef __NR_ftruncate64
    org_sys_table[__NR_ftruncate64] = sys_call_table[__NR_ftruncate64];
#endif
#endif

#ifdef __NR_setxattr
    org_sys_table[__NR_setxattr] = sys_call_table[__NR_setxattr];
#endif
#ifdef __NR_lsetxattr
    org_sys_table[__NR_lsetxattr] = sys_call_table[__NR_lsetxattr];
#endif
#ifdef __NR_fsetxattr
    org_sys_table[__NR_fsetxattr] = sys_call_table[__NR_fsetxattr];
#endif
#ifdef __NR_getxattr
    org_sys_table[__NR_getxattr] = sys_call_table[__NR_getxattr];
#endif
#ifdef __NR_lgetxattr
    org_sys_table[__NR_lgetxattr] = sys_call_table[__NR_lgetxattr];
#endif
#ifdef __NR_fgetxattr
    org_sys_table[__NR_fgetxattr] = sys_call_table[__NR_fgetxattr];
#endif
#ifdef __NR_listxattr
    org_sys_table[__NR_listxattr] = sys_call_table[__NR_listxattr];
#endif
#ifdef __NR_llistxattr
    org_sys_table[__NR_llistxattr] = sys_call_table[__NR_llistxattr];
#endif
#ifdef __NR_flistxattr
    org_sys_table[__NR_flistxattr] = sys_call_table[__NR_flistxattr];
#endif
#ifdef __NR_removexattr
    org_sys_table[__NR_removexattr] = sys_call_table[__NR_removexattr];
#endif
#ifdef __NR_lremovexattr
    org_sys_table[__NR_lremovexattr] = sys_call_table[__NR_lremovexattr];
#endif
#ifdef __NR_fremovexattr
    org_sys_table[__NR_fremovexattr] = sys_call_table[__NR_fremovexattr];
#endif

#ifdef __NR_brk
    org_sys_table[__NR_brk] = sys_call_table[__NR_brk];
#endif
#ifdef __NR_mprotect
    org_sys_table[__NR_mprotect] = sys_call_table[__NR_mprotect];
#endif
#ifdef __NR_mremap
    org_sys_table[__NR_mremap] = sys_call_table[__NR_mremap];
#endif
#ifdef __NR_remap_file_pages
    org_sys_table[__NR_remap_file_pages] = sys_call_table[__NR_remap_file_pages];
#endif
#ifdef __NR_msync
    org_sys_table[__NR_msync] = sys_call_table[__NR_msync];
#endif
#ifdef __NR_fadvise64
    org_sys_table[__NR_fadvise64] = sys_call_table[__NR_fadvise64];
#endif
#ifdef __NR_fadvise64_64
    org_sys_table[__NR_fadvise64_64] = sys_call_table[__NR_fadvise64_64];
#endif
#ifdef __NR_munmap
    org_sys_table[__NR_munmap] = sys_call_table[__NR_munmap];
#endif
#ifdef __NR_mlock
    org_sys_table[__NR_mlock] = sys_call_table[__NR_mlock];
#endif
#ifdef __NR_munlock
    org_sys_table[__NR_munlock] = sys_call_table[__NR_munlock];
#endif
#ifdef __NR_mlockall
    org_sys_table[__NR_mlockall] = sys_call_table[__NR_mlockall];
#endif
#ifdef __NR_munlockall
    org_sys_table[__NR_munlockall] = sys_call_table[__NR_munlockall];
#endif
#ifdef __NR_madvise
    org_sys_table[__NR_madvise] = sys_call_table[__NR_madvise];
#endif
#ifdef __NR_mincore
    org_sys_table[__NR_mincore] = sys_call_table[__NR_mincore];
#endif

#ifdef __NR_pivot_root
    org_sys_table[__NR_pivot_root] = sys_call_table[__NR_pivot_root];
#endif
#ifdef __NR_chroot
    org_sys_table[__NR_chroot] = sys_call_table[__NR_chroot];
#endif
#ifdef __NR_mknod
    org_sys_table[__NR_mknod] = sys_call_table[__NR_mknod];
#endif
#ifdef __NR_link
    org_sys_table[__NR_link] = sys_call_table[__NR_link];
#endif
#ifdef __NR_symlink
    org_sys_table[__NR_symlink] = sys_call_table[__NR_symlink];
#endif
#ifdef __NR_unlink
    org_sys_table[__NR_unlink] = sys_call_table[__NR_unlink];
#endif
#ifdef __NR_rename
    org_sys_table[__NR_rename] = sys_call_table[__NR_rename];
#endif
#ifdef __NR_chmod
    org_sys_table[__NR_chmod] = sys_call_table[__NR_chmod];
#endif
#ifdef __NR_fchmod
    org_sys_table[__NR_fchmod] = sys_call_table[__NR_fchmod];
#endif

#ifdef __NR_fcntl
    org_sys_table[__NR_fcntl] = sys_call_table[__NR_fcntl];
#endif
#if BITS_PER_LONG == 32
#ifdef __NR_fcntl64
    org_sys_table[__NR_fcntl64] = sys_call_table[__NR_fcntl64];
#endif
#endif
#ifdef __NR_pipe
    org_sys_table[__NR_pipe] = sys_call_table[__NR_pipe];
#endif
#ifdef __NR_pipe2
    org_sys_table[__NR_pipe2] = sys_call_table[__NR_pipe2];
#endif
#ifdef __NR_dup
    org_sys_table[__NR_dup] = sys_call_table[__NR_dup];
#endif
#ifdef __NR_dup2
    org_sys_table[__NR_dup2] = sys_call_table[__NR_dup2];
#endif
#ifdef __NR_dup3
    org_sys_table[__NR_dup3] = sys_call_table[__NR_dup3];
#endif
#ifdef __NR_ioperm
    org_sys_table[__NR_ioperm] = sys_call_table[__NR_ioperm];
#endif
#ifdef __NR_ioctl
    org_sys_table[__NR_ioctl] = sys_call_table[__NR_ioctl];
#endif
#ifdef __NR_flock
    org_sys_table[__NR_flock] = sys_call_table[__NR_flock];
#endif
#ifdef __NR_io_setup
    org_sys_table[__NR_io_setup] = sys_call_table[__NR_io_setup];
#endif
#ifdef __NR_io_destroy
    org_sys_table[__NR_io_destroy] = sys_call_table[__NR_io_destroy];
#endif
#ifdef __NR_io_getevents
    org_sys_table[__NR_io_getevents] = sys_call_table[__NR_io_getevents];
#endif
#ifdef __NR_io_submit
    org_sys_table[__NR_io_submit] = sys_call_table[__NR_io_submit];
#endif
#ifdef __NR_io_cancel
    org_sys_table[__NR_io_cancel] = sys_call_table[__NR_io_cancel];
#endif
#ifdef __NR_sendfile
    org_sys_table[__NR_sendfile] = sys_call_table[__NR_sendfile];
#endif
#ifdef __NR_sendfile64
    org_sys_table[__NR_sendfile64] = sys_call_table[__NR_sendfile64];
#endif
#ifdef __NR_readlink
    org_sys_table[__NR_readlink] = sys_call_table[__NR_readlink];
#endif
#ifdef __NR_creat
    org_sys_table[__NR_creat] = sys_call_table[__NR_creat];
#endif
#ifdef __NR_open
    org_sys_table[__NR_open] = sys_call_table[__NR_open];
#endif
#ifdef __NR_close
    org_sys_table[__NR_close] = sys_call_table[__NR_close];
#endif
#ifdef __NR_access
    org_sys_table[__NR_access] = sys_call_table[__NR_access];
#endif
#ifdef __NR_vhangup
    org_sys_table[__NR_vhangup] = sys_call_table[__NR_vhangup];
#endif
#ifdef __NR_chown
    org_sys_table[__NR_chown] = sys_call_table[__NR_chown];
#endif
#ifdef __NR_lchown
    org_sys_table[__NR_lchown] = sys_call_table[__NR_lchown];
#endif
#ifdef __NR_fchown
    org_sys_table[__NR_fchown] = sys_call_table[__NR_fchown];
#endif
#ifdef CONFIG_HAVE_UID16
#ifdef __NR_chown16
    org_sys_table[__NR_chown16] = sys_call_table[__NR_chown16];
#endif
#ifdef __NR_lchown16
    org_sys_table[__NR_lchown16] = sys_call_table[__NR_lchown16];
#endif
#ifdef __NR_fchown16
    org_sys_table[__NR_fchown16] = sys_call_table[__NR_fchown16];
#endif
#ifdef __NR_setregid16
    org_sys_table[__NR_setregid16] = sys_call_table[__NR_setregid16];
#endif
#ifdef __NR_setgid16
    org_sys_table[__NR_setgid16] = sys_call_table[__NR_setgid16];
#endif
#ifdef __NR_setreuid16
    org_sys_table[__NR_setreuid16] = sys_call_table[__NR_setreuid16];
#endif
#ifdef __NR_setuid16
    org_sys_table[__NR_setuid16] = sys_call_table[__NR_setuid16];
#endif
#ifdef __NR_setresuid16
    org_sys_table[__NR_setresuid16] = sys_call_table[__NR_setresuid16];
#endif
#ifdef __NR_getresuid16
    org_sys_table[__NR_getresuid16] = sys_call_table[__NR_getresuid16];
#endif
#ifdef __NR_setresgid16
    org_sys_table[__NR_setresgid16] = sys_call_table[__NR_setresgid16];
#endif
#ifdef __NR_getresgid16
    org_sys_table[__NR_getresgid16] = sys_call_table[__NR_getresgid16];
#endif
#ifdef __NR_setfsuid16
    org_sys_table[__NR_setfsuid16] = sys_call_table[__NR_setfsuid16];
#endif
#ifdef __NR_setfsgid16
    org_sys_table[__NR_setfsgid16] = sys_call_table[__NR_setfsgid16];
#endif
#ifdef __NR_getgroups16
    org_sys_table[__NR_getgroups16] = sys_call_table[__NR_getgroups16];
#endif
#ifdef __NR_setgroups16
    org_sys_table[__NR_setgroups16] = sys_call_table[__NR_setgroups16];
#endif
#ifdef __NR_getuid16
    org_sys_table[__NR_getuid16] = sys_call_table[__NR_getuid16];
#endif
#ifdef __NR_geteuid16
    org_sys_table[__NR_geteuid16] = sys_call_table[__NR_geteuid16];
#endif
#ifdef __NR_getgid16
    org_sys_table[__NR_getgid16] = sys_call_table[__NR_getgid16];
#endif
#ifdef __NR_getegid16
    org_sys_table[__NR_getegid16] = sys_call_table[__NR_getegid16];
#endif
#endif

#ifdef __NR_utime
    org_sys_table[__NR_utime] = sys_call_table[__NR_utime];
#endif
#ifdef __NR_utimes
    org_sys_table[__NR_utimes] = sys_call_table[__NR_utimes];
#endif
#ifdef __NR_lseek
    org_sys_table[__NR_lseek] = sys_call_table[__NR_lseek];
#endif
#ifdef __NR_llseek
    org_sys_table[__NR_llseek] = sys_call_table[__NR_llseek];
#endif
#ifdef __NR_read
    org_sys_table[__NR_read] = sys_call_table[__NR_read];
#endif
#ifdef __NR_readahead
    org_sys_table[__NR_readahead] = sys_call_table[__NR_readahead];
#endif
#ifdef __NR_readv
    org_sys_table[__NR_readv] = sys_call_table[__NR_readv];
#endif
#ifdef __NR_write
    org_sys_table[__NR_write] = sys_call_table[__NR_write];
#endif
#ifdef __NR_writev
    org_sys_table[__NR_writev] = sys_call_table[__NR_writev];
#endif
#ifdef __NR_pread64
    org_sys_table[__NR_pread64] = sys_call_table[__NR_pread64];
#endif
#ifdef __NR_pwrite64
    org_sys_table[__NR_pwrite64] = sys_call_table[__NR_pwrite64];
#endif
#ifdef __NR_preadv
    org_sys_table[__NR_preadv] = sys_call_table[__NR_preadv];
#endif
#ifdef __NR_preadv2
    org_sys_table[__NR_preadv2] = sys_call_table[__NR_preadv2];
#endif
#ifdef __NR_pwritev
    org_sys_table[__NR_pwritev] = sys_call_table[__NR_pwritev];
#endif
#ifdef __NR_pwritev2
    org_sys_table[__NR_pwritev2] = sys_call_table[__NR_pwritev2];
#endif
#ifdef __NR_getcwd
    org_sys_table[__NR_getcwd] = sys_call_table[__NR_getcwd];
#endif
#ifdef __NR_mkdir
    org_sys_table[__NR_mkdir] = sys_call_table[__NR_mkdir];
#endif
#ifdef __NR_chdir
    org_sys_table[__NR_chdir] = sys_call_table[__NR_chdir];
#endif
#ifdef __NR_fchdir
    org_sys_table[__NR_fchdir] = sys_call_table[__NR_fchdir];
#endif
#ifdef __NR_rmdir
    org_sys_table[__NR_rmdir] = sys_call_table[__NR_rmdir];
#endif
#ifdef __NR_lookup_dcookie
    org_sys_table[__NR_lookup_dcookie] = sys_call_table[__NR_lookup_dcookie];
#endif
#ifdef __NR_quotactl
    org_sys_table[__NR_quotactl] = sys_call_table[__NR_quotactl];
#endif
#ifdef __NR_getdents
    org_sys_table[__NR_getdents] = sys_call_table[__NR_getdents];
#endif
#ifdef __NR_getdents64
    org_sys_table[__NR_getdents64] = sys_call_table[__NR_getdents64];
#endif

#ifdef __NR_setsockopt
    org_sys_table[__NR_setsockopt] = sys_call_table[__NR_setsockopt];
#endif
#ifdef __NR_getsockopt
    org_sys_table[__NR_getsockopt] = sys_call_table[__NR_getsockopt];
#endif
#ifdef __NR_bind
    org_sys_table[__NR_bind] = sys_call_table[__NR_bind];
#endif
#ifdef __NR_connect
    org_sys_table[__NR_connect] = sys_call_table[__NR_connect];
#endif
#ifdef __NR_accept
    org_sys_table[__NR_accept] = sys_call_table[__NR_accept];
#endif
#ifdef __NR_accept4
    org_sys_table[__NR_accept4] = sys_call_table[__NR_accept4];
#endif
#ifdef __NR_getsockname
    org_sys_table[__NR_getsockname] = sys_call_table[__NR_getsockname];
#endif
#ifdef __NR_getpeername
    org_sys_table[__NR_getpeername] = sys_call_table[__NR_getpeername];
#endif
#ifdef __NR_send
    org_sys_table[__NR_send] = sys_call_table[__NR_send];
#endif
#ifdef __NR_sendto
    org_sys_table[__NR_sendto] = sys_call_table[__NR_sendto];
#endif
#ifdef __NR_sendmsg
    org_sys_table[__NR_sendmsg] = sys_call_table[__NR_sendmsg];
#endif
#ifdef __NR_sendmmsg
    org_sys_table[__NR_sendmmsg] = sys_call_table[__NR_sendmmsg];
#endif
#ifdef __NR_recv
    org_sys_table[__NR_recv] = sys_call_table[__NR_recv];
#endif
#ifdef __NR_recvfrom
    org_sys_table[__NR_recvfrom] = sys_call_table[__NR_recvfrom];
#endif
#ifdef __NR_recvmsg
    org_sys_table[__NR_recvmsg] = sys_call_table[__NR_recvmsg];
#endif
#ifdef __NR_recvmmsg
    org_sys_table[__NR_recvmmsg] = sys_call_table[__NR_recvmmsg];
#endif
#ifdef __NR_socket
    org_sys_table[__NR_socket] = sys_call_table[__NR_socket];
#endif
#ifdef __NR_socketpair
    org_sys_table[__NR_socketpair] = sys_call_table[__NR_socketpair];
#endif
#ifdef __NR_socketcall
    org_sys_table[__NR_socketcall] = sys_call_table[__NR_socketcall];
#endif
#ifdef __NR_listen
    org_sys_table[__NR_listen] = sys_call_table[__NR_listen];
#endif
#ifdef __NR_poll
    org_sys_table[__NR_poll] = sys_call_table[__NR_poll];
#endif
#ifdef __NR_select
    org_sys_table[__NR_select] = sys_call_table[__NR_select];
#endif
#ifdef __NR_old_select
    org_sys_table[__NR_old_select] = sys_call_table[__NR_old_select];
#endif
#ifdef __NR_epoll_create
    org_sys_table[__NR_epoll_create] = sys_call_table[__NR_epoll_create];
#endif
#ifdef __NR_epoll_create1
    org_sys_table[__NR_epoll_create1] = sys_call_table[__NR_epoll_create1];
#endif
#ifdef __NR_epoll_ctl
    org_sys_table[__NR_epoll_ctl] = sys_call_table[__NR_epoll_ctl];
#endif
#ifdef __NR_epoll_wait
    org_sys_table[__NR_epoll_wait] = sys_call_table[__NR_epoll_wait];
#endif
#ifdef __NR_epoll_pwait
    org_sys_table[__NR_epoll_pwait] = sys_call_table[__NR_epoll_pwait];
#endif
#ifdef __NR_gethostname
    org_sys_table[__NR_gethostname] = sys_call_table[__NR_gethostname];
#endif
#ifdef __NR_sethostname
    org_sys_table[__NR_sethostname] = sys_call_table[__NR_sethostname];
#endif
#ifdef __NR_setdomainname
    org_sys_table[__NR_setdomainname] = sys_call_table[__NR_setdomainname];
#endif
#ifdef __NR_newuname
    org_sys_table[__NR_newuname] = sys_call_table[__NR_newuname];
#endif
#ifdef __NR_uname
    org_sys_table[__NR_uname] = sys_call_table[__NR_uname];
#endif
#ifdef __NR_olduname
    org_sys_table[__NR_olduname] = sys_call_table[__NR_olduname];
#endif

#ifdef __NR_getrlimit
    org_sys_table[__NR_getrlimit] = sys_call_table[__NR_getrlimit];
#endif
#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT
#ifdef __NR_old_getrlimit
    org_sys_table[__NR_old_getrlimit] = sys_call_table[__NR_old_getrlimit];
#endif
#endif
#ifdef __NR_setrlimit
    org_sys_table[__NR_setrlimit] = sys_call_table[__NR_setrlimit];
#endif
#ifdef __NR_prlimit64
    org_sys_table[__NR_prlimit64] = sys_call_table[__NR_prlimit64];
#endif
#ifdef __NR_getrusage
    org_sys_table[__NR_getrusage] = sys_call_table[__NR_getrusage];
#endif
#ifdef __NR_umask
    org_sys_table[__NR_umask] = sys_call_table[__NR_umask];
#endif

#ifdef __NR_msgget
    org_sys_table[__NR_msgget] = sys_call_table[__NR_msgget];
#endif
#ifdef __NR_msgsnd
    org_sys_table[__NR_msgsnd] = sys_call_table[__NR_msgsnd];
#endif
#ifdef __NR_msgrcv
    org_sys_table[__NR_msgrcv] = sys_call_table[__NR_msgrcv];
#endif
#ifdef __NR_msgctl
    org_sys_table[__NR_msgctl] = sys_call_table[__NR_msgctl];
#endif

#ifdef __NR_semget
    org_sys_table[__NR_semget] = sys_call_table[__NR_semget];
#endif
#ifdef __NR_semop
    org_sys_table[__NR_semop] = sys_call_table[__NR_semop];
#endif
#ifdef __NR_semctl
    org_sys_table[__NR_semctl] = sys_call_table[__NR_semctl];
#endif
#ifdef __NR_semtimedop
    org_sys_table[__NR_semtimedop] = sys_call_table[__NR_semtimedop];
#endif
#ifdef __NR_shmat
    org_sys_table[__NR_shmat] = sys_call_table[__NR_shmat];
#endif
#ifdef __NR_shmget
    org_sys_table[__NR_shmget] = sys_call_table[__NR_shmget];
#endif
#ifdef __NR_shmdt
    org_sys_table[__NR_shmdt] = sys_call_table[__NR_shmdt];
#endif
#ifdef __NR_shmctl
    org_sys_table[__NR_shmctl] = sys_call_table[__NR_shmctl];
#endif
#ifdef __NR_ipc
    org_sys_table[__NR_ipc] = sys_call_table[__NR_ipc];
#endif

#ifdef __NR_mq_open
    org_sys_table[__NR_mq_open] = sys_call_table[__NR_mq_open];
#endif
#ifdef __NR_mq_unlink
    org_sys_table[__NR_mq_unlink] = sys_call_table[__NR_mq_unlink];
#endif
#ifdef __NR_mq_timedsend
    org_sys_table[__NR_mq_timedsend] = sys_call_table[__NR_mq_timedsend];
#endif
#ifdef __NR_mq_timedreceive
    org_sys_table[__NR_mq_timedreceive] = sys_call_table[__NR_mq_timedreceive];
#endif
#ifdef __NR_mq_notify
    org_sys_table[__NR_mq_notify] = sys_call_table[__NR_mq_notify];
#endif
#ifdef __NR_mq_getsetattr
    org_sys_table[__NR_mq_getsetattr] = sys_call_table[__NR_mq_getsetattr];
#endif

#ifdef __NR_pciconfig_iobase
    org_sys_table[__NR_pciconfig_iobase] = sys_call_table[__NR_pciconfig_iobase];
#endif
#ifdef __NR_pciconfig_read
    org_sys_table[__NR_pciconfig_read] = sys_call_table[__NR_pciconfig_read];
#endif
#ifdef __NR_pciconfig_write
    org_sys_table[__NR_pciconfig_write] = sys_call_table[__NR_pciconfig_write];
#endif

#ifdef __NR_prctl
    org_sys_table[__NR_prctl] = sys_call_table[__NR_prctl];
#endif
#ifdef __NR_swapon
    org_sys_table[__NR_swapon] = sys_call_table[__NR_swapon];
#endif
#ifdef __NR_swapoff
    org_sys_table[__NR_swapoff] = sys_call_table[__NR_swapoff];
#endif
#ifdef __NR_sysctl
    org_sys_table[__NR_sysctl] = sys_call_table[__NR_sysctl];
#endif
#ifdef __NR_sysinfo
    org_sys_table[__NR_sysinfo] = sys_call_table[__NR_sysinfo];
#endif
#ifdef __NR_sysfs
    org_sys_table[__NR_sysfs] = sys_call_table[__NR_sysfs];
#endif
#ifdef __NR_syslog
    org_sys_table[__NR_syslog] = sys_call_table[__NR_syslog];
#endif
#ifdef __NR_uselib
    org_sys_table[__NR_uselib] = sys_call_table[__NR_uselib];
#endif
#ifdef __NR_ni_syscall
    org_sys_table[__NR_ni_syscall] = sys_call_table[__NR_ni_syscall];
#endif
#ifdef __NR_ptrace
    org_sys_table[__NR_ptrace] = sys_call_table[__NR_ptrace];
#endif

#ifdef __NR_add_key
    org_sys_table[__NR_add_key] = sys_call_table[__NR_add_key];
#endif

#ifdef __NR_request_key
    org_sys_table[__NR_request_key] = sys_call_table[__NR_request_key];
#endif

#ifdef __NR_keyctl
    org_sys_table[__NR_keyctl] = sys_call_table[__NR_keyctl];
#endif

#ifdef __NR_ioprio_set
    org_sys_table[__NR_ioprio_set] = sys_call_table[__NR_ioprio_set];
#endif
#ifdef __NR_ioprio_get
    org_sys_table[__NR_ioprio_get] = sys_call_table[__NR_ioprio_get];
#endif
#ifdef __NR_set_mempolicy
    org_sys_table[__NR_set_mempolicy] = sys_call_table[__NR_set_mempolicy];
#endif
#ifdef __NR_migrate_pages
    org_sys_table[__NR_migrate_pages] = sys_call_table[__NR_migrate_pages];
#endif
#ifdef __NR_move_pages
    org_sys_table[__NR_move_pages] = sys_call_table[__NR_move_pages];
#endif
#ifdef __NR_mbind
    org_sys_table[__NR_mbind] = sys_call_table[__NR_mbind];
#endif
#ifdef __NR_get_mempolicy
    org_sys_table[__NR_get_mempolicy] = sys_call_table[__NR_get_mempolicy];
#endif

#ifdef __NR_inotify_init
    org_sys_table[__NR_inotify_init] = sys_call_table[__NR_inotify_init];
#endif
#ifdef __NR_inotify_init1
    org_sys_table[__NR_inotify_init1] = sys_call_table[__NR_inotify_init1];
#endif
#ifdef __NR_inotify_add_watch
    org_sys_table[__NR_inotify_add_watch] = sys_call_table[__NR_inotify_add_watch];
#endif
#ifdef __NR_inotify_rm_watch
    org_sys_table[__NR_inotify_rm_watch] = sys_call_table[__NR_inotify_rm_watch];
#endif

#ifdef __NR_spu_run
    org_sys_table[__NR_spu_run] = sys_call_table[__NR_spu_run];
#endif
#ifdef __NR_spu_create
    org_sys_table[__NR_spu_create] = sys_call_table[__NR_spu_create];
#endif

#ifdef __NR_mknodat
    org_sys_table[__NR_mknodat] = sys_call_table[__NR_mknodat];
#endif
#ifdef __NR_mkdirat
    org_sys_table[__NR_mkdirat] = sys_call_table[__NR_mkdirat];
#endif
#ifdef __NR_unlinkat
    org_sys_table[__NR_unlinkat] = sys_call_table[__NR_unlinkat];
#endif
#ifdef __NR_symlinkat
    org_sys_table[__NR_symlinkat] = sys_call_table[__NR_symlinkat];
#endif
#ifdef __NR_linkat
    org_sys_table[__NR_linkat] = sys_call_table[__NR_linkat];
#endif
#ifdef __NR_renameat
    org_sys_table[__NR_renameat] = sys_call_table[__NR_renameat];
#endif
#ifdef __NR_renameat2
    org_sys_table[__NR_renameat2] = sys_call_table[__NR_renameat2];
#endif
#ifdef __NR_futimesat
    org_sys_table[__NR_futimesat] = sys_call_table[__NR_futimesat];
#endif
#ifdef __NR_faccessat
    org_sys_table[__NR_faccessat] = sys_call_table[__NR_faccessat];
#endif
#ifdef __NR_fchmodat
    org_sys_table[__NR_fchmodat] = sys_call_table[__NR_fchmodat];
#endif
#ifdef __NR_fchownat
    org_sys_table[__NR_fchownat] = sys_call_table[__NR_fchownat];
#endif
#ifdef __NR_openat
    org_sys_table[__NR_openat] = sys_call_table[__NR_openat];
#endif
#ifdef __NR_newfstatat
    org_sys_table[__NR_newfstatat] = sys_call_table[__NR_newfstatat];
#endif
#ifdef __NR_readlinkat
    org_sys_table[__NR_readlinkat] = sys_call_table[__NR_readlinkat];
#endif
#ifdef __NR_utimensat
    org_sys_table[__NR_utimensat] = sys_call_table[__NR_utimensat];
#endif
#ifdef __NR_unshare
    org_sys_table[__NR_unshare] = sys_call_table[__NR_unshare];
#endif

#ifdef __NR_splice
    org_sys_table[__NR_splice] = sys_call_table[__NR_splice];
#endif

#ifdef __NR_vmsplice
    org_sys_table[__NR_vmsplice] = sys_call_table[__NR_vmsplice];
#endif

#ifdef __NR_tee
    org_sys_table[__NR_tee] = sys_call_table[__NR_tee];
#endif

#ifdef __NR_sync_file_range
    org_sys_table[__NR_sync_file_range] = sys_call_table[__NR_sync_file_range];
#endif
#ifdef __NR_sync_file_range2
    org_sys_table[__NR_sync_file_range2] = sys_call_table[__NR_sync_file_range2];
#endif
#ifdef __NR_get_robust_list
    org_sys_table[__NR_get_robust_list] = sys_call_table[__NR_get_robust_list];
#endif
#ifdef __NR_set_robust_list
    org_sys_table[__NR_set_robust_list] = sys_call_table[__NR_set_robust_list];
#endif
#ifdef __NR_getcpu
    org_sys_table[__NR_getcpu] = sys_call_table[__NR_getcpu];
#endif
#ifdef __NR_signalfd
    org_sys_table[__NR_signalfd] = sys_call_table[__NR_signalfd];
#endif
#ifdef __NR_signalfd4
    org_sys_table[__NR_signalfd4] = sys_call_table[__NR_signalfd4];
#endif
#ifdef __NR_timerfd_create
    org_sys_table[__NR_timerfd_create] = sys_call_table[__NR_timerfd_create];
#endif
#ifdef __NR_timerfd_settime
    org_sys_table[__NR_timerfd_settime] = sys_call_table[__NR_timerfd_settime];
#endif
#ifdef __NR_timerfd_gettime
    org_sys_table[__NR_timerfd_gettime] = sys_call_table[__NR_timerfd_gettime];
#endif
#ifdef __NR_eventfd
    org_sys_table[__NR_eventfd] = sys_call_table[__NR_eventfd];
#endif
#ifdef __NR_eventfd2
    org_sys_table[__NR_eventfd2] = sys_call_table[__NR_eventfd2];
#endif
#ifdef __NR_memfd_create
    org_sys_table[__NR_memfd_create] = sys_call_table[__NR_memfd_create];
#endif
#ifdef __NR_userfaultfd
    org_sys_table[__NR_userfaultfd] = sys_call_table[__NR_userfaultfd];
#endif
#ifdef __NR_fallocate
    org_sys_table[__NR_fallocate] = sys_call_table[__NR_fallocate];
#endif
#ifdef __NR_old_readdir
    org_sys_table[__NR_old_readdir] = sys_call_table[__NR_old_readdir];
#endif
#ifdef __NR_pselect6
    org_sys_table[__NR_pselect6] = sys_call_table[__NR_pselect6];
#endif
#ifdef __NR_ppoll
    org_sys_table[__NR_ppoll] = sys_call_table[__NR_ppoll];
#endif
#ifdef __NR_fanotify_init
    org_sys_table[__NR_fanotify_init] = sys_call_table[__NR_fanotify_init];
#endif
#ifdef __NR_fanotify_mark
    org_sys_table[__NR_fanotify_mark] = sys_call_table[__NR_fanotify_mark];
#endif
#ifdef __NR_syncfs
    org_sys_table[__NR_syncfs] = sys_call_table[__NR_syncfs];
#endif

#ifdef __NR_fork
    org_sys_table[__NR_fork] = sys_call_table[__NR_fork];
#endif
#ifdef __NR_vfork
    org_sys_table[__NR_vfork] = sys_call_table[__NR_vfork];
#endif
#ifdef CONFIG_CLONE_BACKWARDS
#ifdef __NR_clone
    org_sys_table[__NR_clone] = sys_call_table[__NR_clone];
#endif
#else
#ifdef CONFIG_CLONE_BACKWARDS3
#ifdef __NR_clone
    org_sys_table[__NR_clone] = sys_call_table[__NR_clone];
#endif
#else
#ifdef __NR_clone
    org_sys_table[__NR_clone] = sys_call_table[__NR_clone];
#endif
#endif
#endif

#ifdef __NR_execve
    org_sys_table[__NR_execve] = sys_call_table[__NR_execve];
#endif

#ifdef __NR_perf_event_open
    org_sys_table[__NR_perf_event_open] = sys_call_table[__NR_perf_event_open];
#endif

#ifdef __NR_mmap_pgoff
    org_sys_table[__NR_mmap_pgoff] = sys_call_table[__NR_mmap_pgoff];
#endif
#ifdef __NR_old_mmap
    org_sys_table[__NR_old_mmap] = sys_call_table[__NR_old_mmap];
#endif
#ifdef __NR_name_to_handle_at
    org_sys_table[__NR_name_to_handle_at] = sys_call_table[__NR_name_to_handle_at];
#endif
#ifdef __NR_open_by_handle_at
    org_sys_table[__NR_open_by_handle_at] = sys_call_table[__NR_open_by_handle_at];
#endif
#ifdef __NR_setns
    org_sys_table[__NR_setns] = sys_call_table[__NR_setns];
#endif
#ifdef __NR_process_vm_readv
    org_sys_table[__NR_process_vm_readv] = sys_call_table[__NR_process_vm_readv];
#endif
#ifdef __NR_process_vm_writev
    org_sys_table[__NR_process_vm_writev] = sys_call_table[__NR_process_vm_writev];
#endif

#ifdef __NR_kcmp
    org_sys_table[__NR_kcmp] = sys_call_table[__NR_kcmp];
#endif
#ifdef __NR_finit_module
    org_sys_table[__NR_finit_module] = sys_call_table[__NR_finit_module];
#endif
#ifdef __NR_seccomp
    org_sys_table[__NR_seccomp] = sys_call_table[__NR_seccomp];
#endif
#ifdef __NR_getrandom
    org_sys_table[__NR_getrandom] = sys_call_table[__NR_getrandom];
#endif
#ifdef __NR_bpf
    org_sys_table[__NR_bpf] = sys_call_table[__NR_bpf];
#endif

#ifdef __NR_execveat
    org_sys_table[__NR_execveat] = sys_call_table[__NR_execveat];
#endif

#ifdef __NR_membarrier
    org_sys_table[__NR_membarrier] = sys_call_table[__NR_membarrier];
#endif
#ifdef __NR_copy_file_range
    org_sys_table[__NR_copy_file_range] = sys_call_table[__NR_copy_file_range];
#endif

#ifdef __NR_mlock2
    org_sys_table[__NR_mlock2] = sys_call_table[__NR_mlock2];
#endif

#ifdef __NR_pkey_mprotect
    org_sys_table[__NR_pkey_mprotect] = sys_call_table[__NR_pkey_mprotect];
#endif
#ifdef __NR_pkey_alloc
    org_sys_table[__NR_pkey_alloc] = sys_call_table[__NR_pkey_alloc];
#endif
#ifdef __NR_pkey_free
    org_sys_table[__NR_pkey_free] = sys_call_table[__NR_pkey_free];
#endif
#ifdef __NR_statx
    org_sys_table[__NR_statx] = sys_call_table[__NR_statx];
#endif

// Reassigning the original syscall table entries to point to custom syscall functions
    
    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));
    
#ifdef __NR_time
    sys_call_table[__NR_time] = (sys_call_ptr_t)custom_time;
#endif
#ifdef __NR_stime
    sys_call_table[__NR_stime] = (sys_call_ptr_t)custom_stime;
#endif
#ifdef __NR_gettimeofday
    sys_call_table[__NR_gettimeofday] = (sys_call_ptr_t)custom_gettimeofday;
#endif
#ifdef __NR_settimeofday
    sys_call_table[__NR_settimeofday] = (sys_call_ptr_t)custom_settimeofday;
#endif
#ifdef __NR_adjtimex
    sys_call_table[__NR_adjtimex] = (sys_call_ptr_t)custom_adjtimex;
#endif

#ifdef __NR_times
    sys_call_table[__NR_times] = (sys_call_ptr_t)custom_times;
#endif

#ifdef __NR_gettid
    sys_call_table[__NR_gettid] = (sys_call_ptr_t)custom_gettid;
#endif
#ifdef __NR_nanosleep
    sys_call_table[__NR_nanosleep] = (sys_call_ptr_t)custom_nanosleep;
#endif
#ifdef __NR_alarm
    sys_call_table[__NR_alarm] = (sys_call_ptr_t)custom_alarm;
#endif
#ifdef __NR_getpid
    sys_call_table[__NR_getpid] = (sys_call_ptr_t)custom_getpid;
#endif
#ifdef __NR_getppid
    sys_call_table[__NR_getppid] = (sys_call_ptr_t)custom_getppid;
#endif
#ifdef __NR_getuid
    sys_call_table[__NR_getuid] = (sys_call_ptr_t)custom_getuid;
#endif
#ifdef __NR_geteuid
    sys_call_table[__NR_geteuid] = (sys_call_ptr_t)custom_geteuid;
#endif
#ifdef __NR_getgid
    sys_call_table[__NR_getgid] = (sys_call_ptr_t)custom_getgid;
#endif
#ifdef __NR_getegid
    sys_call_table[__NR_getegid] = (sys_call_ptr_t)custom_getegid;
#endif
#ifdef __NR_getresuid
    sys_call_table[__NR_getresuid] = (sys_call_ptr_t)custom_getresuid;
#endif
#ifdef __NR_getresgid
    sys_call_table[__NR_getresgid] = (sys_call_ptr_t)custom_getresgid;
#endif
#ifdef __NR_getpgid
    sys_call_table[__NR_getpgid] = (sys_call_ptr_t)custom_getpgid;
#endif
#ifdef __NR_getpgrp
    sys_call_table[__NR_getpgrp] = (sys_call_ptr_t)custom_getpgrp;
#endif
#ifdef __NR_getsid
    sys_call_table[__NR_getsid] = (sys_call_ptr_t)custom_getsid;
#endif
#ifdef __NR_getgroups
    sys_call_table[__NR_getgroups] = (sys_call_ptr_t)custom_getgroups;
#endif

#ifdef __NR_setregid
    sys_call_table[__NR_setregid] = (sys_call_ptr_t)custom_setregid;
#endif
#ifdef __NR_setgid
    sys_call_table[__NR_setgid] = (sys_call_ptr_t)custom_setgid;
#endif
#ifdef __NR_setreuid
    sys_call_table[__NR_setreuid] = (sys_call_ptr_t)custom_setreuid;
#endif
#ifdef __NR_setuid
    sys_call_table[__NR_setuid] = (sys_call_ptr_t)custom_setuid;
#endif
#ifdef __NR_setresuid
    sys_call_table[__NR_setresuid] = (sys_call_ptr_t)custom_setresuid;
#endif
#ifdef __NR_setresgid
    sys_call_table[__NR_setresgid] = (sys_call_ptr_t)custom_setresgid;
#endif
#ifdef __NR_setfsuid
    sys_call_table[__NR_setfsuid] = (sys_call_ptr_t)custom_setfsuid;
#endif
#ifdef __NR_setfsgid
    sys_call_table[__NR_setfsgid] = (sys_call_ptr_t)custom_setfsgid;
#endif
#ifdef __NR_setpgid
    sys_call_table[__NR_setpgid] = (sys_call_ptr_t)custom_setpgid;
#endif
#ifdef __NR_setsid
    sys_call_table[__NR_setsid] = (sys_call_ptr_t)custom_setsid;
#endif
#ifdef __NR_setgroups
    sys_call_table[__NR_setgroups] = (sys_call_ptr_t)custom_setgroups;
#endif

#ifdef __NR_acct
    sys_call_table[__NR_acct] = (sys_call_ptr_t)custom_acct;
#endif
#ifdef __NR_capget
    sys_call_table[__NR_capget] = (sys_call_ptr_t)custom_capget;
#endif
#ifdef __NR_capset
    sys_call_table[__NR_capset] = (sys_call_ptr_t)custom_capset;
#endif
#ifdef __NR_personality
    sys_call_table[__NR_personality] = (sys_call_ptr_t)custom_personality;
#endif

#ifdef __NR_sigpending
    sys_call_table[__NR_sigpending] = (sys_call_ptr_t)custom_sigpending;
#endif
#ifdef __NR_sigprocmask
    sys_call_table[__NR_sigprocmask] = (sys_call_ptr_t)custom_sigprocmask;
#endif
#ifdef __NR_sigaltstack
    sys_call_table[__NR_sigaltstack] = (sys_call_ptr_t)custom_sigaltstack;
#endif

#ifdef __NR_getitimer
    sys_call_table[__NR_getitimer] = (sys_call_ptr_t)custom_getitimer;
#endif
#ifdef __NR_setitimer
    sys_call_table[__NR_setitimer] = (sys_call_ptr_t)custom_setitimer;
#endif
#ifdef __NR_timer_create
    sys_call_table[__NR_timer_create] = (sys_call_ptr_t)custom_timer_create;
#endif
#ifdef __NR_timer_gettime
    sys_call_table[__NR_timer_gettime] = (sys_call_ptr_t)custom_timer_gettime;
#endif
#ifdef __NR_timer_getoverrun
    sys_call_table[__NR_timer_getoverrun] = (sys_call_ptr_t)custom_timer_getoverrun;
#endif
#ifdef __NR_timer_settime
    sys_call_table[__NR_timer_settime] = (sys_call_ptr_t)custom_timer_settime;
#endif
#ifdef __NR_timer_delete
    sys_call_table[__NR_timer_delete] = (sys_call_ptr_t)custom_timer_delete;
#endif
#ifdef __NR_clock_settime
    sys_call_table[__NR_clock_settime] = (sys_call_ptr_t)custom_clock_settime;
#endif
#ifdef __NR_clock_gettime
    sys_call_table[__NR_clock_gettime] = (sys_call_ptr_t)custom_clock_gettime;
#endif
#ifdef __NR_clock_adjtime
    sys_call_table[__NR_clock_adjtime] = (sys_call_ptr_t)custom_clock_adjtime;
#endif
#ifdef __NR_clock_getres
    sys_call_table[__NR_clock_getres] = (sys_call_ptr_t)custom_clock_getres;
#endif
#ifdef __NR_clock_nanosleep
    sys_call_table[__NR_clock_nanosleep] = (sys_call_ptr_t)custom_clock_nanosleep;
#endif

#ifdef __NR_nice
    sys_call_table[__NR_nice] = (sys_call_ptr_t)custom_nice;
#endif
#ifdef __NR_sched_setscheduler
    sys_call_table[__NR_sched_setscheduler] = (sys_call_ptr_t)custom_sched_setscheduler;
#endif
#ifdef __NR_sched_setparam
    sys_call_table[__NR_sched_setparam] = (sys_call_ptr_t)custom_sched_setparam;
#endif
#ifdef __NR_sched_setattr
    sys_call_table[__NR_sched_setattr] = (sys_call_ptr_t)custom_sched_setattr;
#endif
#ifdef __NR_sched_getscheduler
    sys_call_table[__NR_sched_getscheduler] = (sys_call_ptr_t)custom_sched_getscheduler;
#endif
#ifdef __NR_sched_getparam
    sys_call_table[__NR_sched_getparam] = (sys_call_ptr_t)custom_sched_getparam;
#endif
#ifdef __NR_sched_getattr
    sys_call_table[__NR_sched_getattr] = (sys_call_ptr_t)custom_sched_getattr;
#endif
#ifdef __NR_sched_setaffinity
    sys_call_table[__NR_sched_setaffinity] = (sys_call_ptr_t)custom_sched_setaffinity;
#endif
#ifdef __NR_sched_getaffinity
    sys_call_table[__NR_sched_getaffinity] = (sys_call_ptr_t)custom_sched_getaffinity;
#endif
#ifdef __NR_sched_yield
    sys_call_table[__NR_sched_yield] = (sys_call_ptr_t)custom_sched_yield;
#endif
#ifdef __NR_sched_get_priority_max
    sys_call_table[__NR_sched_get_priority_max] = (sys_call_ptr_t)custom_sched_get_priority_max;
#endif
#ifdef __NR_sched_get_priority_min
    sys_call_table[__NR_sched_get_priority_min] = (sys_call_ptr_t)custom_sched_get_priority_min;
#endif
#ifdef __NR_sched_rr_get_interval
    sys_call_table[__NR_sched_rr_get_interval] = (sys_call_ptr_t)custom_sched_rr_get_interval;
#endif
#ifdef __NR_setpriority
    sys_call_table[__NR_setpriority] = (sys_call_ptr_t)custom_setpriority;
#endif
#ifdef __NR_getpriority
    sys_call_table[__NR_getpriority] = (sys_call_ptr_t)custom_getpriority;
#endif

#ifdef __NR_shutdown
    sys_call_table[__NR_shutdown] = (sys_call_ptr_t)custom_shutdown;
#endif
#ifdef __NR_reboot
    sys_call_table[__NR_reboot] = (sys_call_ptr_t)custom_reboot;
#endif
#ifdef __NR_restart_syscall
    sys_call_table[__NR_restart_syscall] = (sys_call_ptr_t)custom_restart_syscall;
#endif
#ifdef __NR_kexec_load
    sys_call_table[__NR_kexec_load] = (sys_call_ptr_t)custom_kexec_load;
#endif
#ifdef __NR_kexec_file_load
    sys_call_table[__NR_kexec_file_load] = (sys_call_ptr_t)custom_kexec_file_load;
#endif

#ifdef __NR_exit
    sys_call_table[__NR_exit] = (sys_call_ptr_t)custom_exit;
#endif
#ifdef __NR_exit_group
    sys_call_table[__NR_exit_group] = (sys_call_ptr_t)custom_exit_group;
#endif
#ifdef __NR_wait4
    sys_call_table[__NR_wait4] = (sys_call_ptr_t)custom_wait4;
#endif
#ifdef __NR_waitid
    sys_call_table[__NR_waitid] = (sys_call_ptr_t)custom_waitid;
#endif
#ifdef __NR_waitpid
    sys_call_table[__NR_waitpid] = (sys_call_ptr_t)custom_waitpid;
#endif
#ifdef __NR_set_tid_address
    sys_call_table[__NR_set_tid_address] = (sys_call_ptr_t)custom_set_tid_address;
#endif
#ifdef __NR_futex
    sys_call_table[__NR_futex] = (sys_call_ptr_t)custom_futex;
#endif

#ifdef __NR_init_module
    sys_call_table[__NR_init_module] = (sys_call_ptr_t)custom_init_module;
#endif
#ifdef __NR_delete_module
    sys_call_table[__NR_delete_module] = (sys_call_ptr_t)custom_delete_module;
#endif

#ifdef CONFIG_OLD_SIGSUSPEND
#ifdef __NR_sigsuspend
    sys_call_table[__NR_sigsuspend] = (sys_call_ptr_t)custom_sigsuspend;
#endif
#endif

#ifdef CONFIG_OLD_SIGSUSPEND3
#ifdef __NR_sigsuspend
    sys_call_table[__NR_sigsuspend] = (sys_call_ptr_t)custom_sigsuspend;
#endif
#endif

#ifdef __NR_rt_sigsuspend
    sys_call_table[__NR_rt_sigsuspend] = (sys_call_ptr_t)custom_rt_sigsuspend;
#endif

#ifdef CONFIG_OLD_SIGACTION
#ifdef __NR_sigaction
    sys_call_table[__NR_sigaction] = (sys_call_ptr_t)custom_sigaction;
#endif
#endif

#ifndef CONFIG_ODD_RT_SIGACTION
#ifdef __NR_rt_sigaction
    sys_call_table[__NR_rt_sigaction] = (sys_call_ptr_t)custom_rt_sigaction;
#endif
#endif
#ifdef __NR_rt_sigprocmask
    sys_call_table[__NR_rt_sigprocmask] = (sys_call_ptr_t)custom_rt_sigprocmask;
#endif
#ifdef __NR_rt_sigpending
    sys_call_table[__NR_rt_sigpending] = (sys_call_ptr_t)custom_rt_sigpending;
#endif
#ifdef __NR_rt_sigtimedwait
    sys_call_table[__NR_rt_sigtimedwait] = (sys_call_ptr_t)custom_rt_sigtimedwait;
#endif
#ifdef __NR_rt_tgsigqueueinfo
    sys_call_table[__NR_rt_tgsigqueueinfo] = (sys_call_ptr_t)custom_rt_tgsigqueueinfo;
#endif
#ifdef __NR_kill
    sys_call_table[__NR_kill] = (sys_call_ptr_t)custom_kill;
#endif
#ifdef __NR_tgkill
    sys_call_table[__NR_tgkill] = (sys_call_ptr_t)custom_tgkill;
#endif
#ifdef __NR_tkill
    sys_call_table[__NR_tkill] = (sys_call_ptr_t)custom_tkill;
#endif
#ifdef __NR_rt_sigqueueinfo
    sys_call_table[__NR_rt_sigqueueinfo] = (sys_call_ptr_t)custom_rt_sigqueueinfo;
#endif
#ifdef __NR_sgetmask
    sys_call_table[__NR_sgetmask] = (sys_call_ptr_t)custom_sgetmask;
#endif
#ifdef __NR_ssetmask
    sys_call_table[__NR_ssetmask] = (sys_call_ptr_t)custom_ssetmask;
#endif
#ifdef __NR_signal
    sys_call_table[__NR_signal] = (sys_call_ptr_t)custom_signal;
#endif
#ifdef __NR_pause
    sys_call_table[__NR_pause] = (sys_call_ptr_t)custom_pause;
#endif

#ifdef __NR_sync
    sys_call_table[__NR_sync] = (sys_call_ptr_t)custom_sync;
#endif
#ifdef __NR_fsync
    sys_call_table[__NR_fsync] = (sys_call_ptr_t)custom_fsync;
#endif
#ifdef __NR_fdatasync
    sys_call_table[__NR_fdatasync] = (sys_call_ptr_t)custom_fdatasync;
#endif
#ifdef __NR_bdflush
    sys_call_table[__NR_bdflush] = (sys_call_ptr_t)custom_bdflush;
#endif
#ifdef __NR_mount
    sys_call_table[__NR_mount] = (sys_call_ptr_t)custom_mount;
#endif
#ifdef __NR_umount
    sys_call_table[__NR_umount] = (sys_call_ptr_t)custom_umount;
#endif
#ifdef __NR_oldumount
    sys_call_table[__NR_oldumount] = (sys_call_ptr_t)custom_oldumount;
#endif
#ifdef __NR_truncate
    sys_call_table[__NR_truncate] = (sys_call_ptr_t)custom_truncate;
#endif
#ifdef __NR_ftruncate
    sys_call_table[__NR_ftruncate] = (sys_call_ptr_t)custom_ftruncate;
#endif
#ifdef __NR_stat
    sys_call_table[__NR_stat] = (sys_call_ptr_t)custom_stat;
#endif
#ifdef __NR_statfs
    sys_call_table[__NR_statfs] = (sys_call_ptr_t)custom_statfs;
#endif
#ifdef __NR_statfs64
    sys_call_table[__NR_statfs64] = (sys_call_ptr_t)custom_statfs64;
#endif
#ifdef __NR_fstatfs
    sys_call_table[__NR_fstatfs] = (sys_call_ptr_t)custom_fstatfs;
#endif
#ifdef __NR_fstatfs64
    sys_call_table[__NR_fstatfs64] = (sys_call_ptr_t)custom_fstatfs64;
#endif
#ifdef __NR_lstat
    sys_call_table[__NR_lstat] = (sys_call_ptr_t)custom_lstat;
#endif
#ifdef __NR_fstat
    sys_call_table[__NR_fstat] = (sys_call_ptr_t)custom_fstat;
#endif
#ifdef __NR_newstat
    sys_call_table[__NR_newstat] = (sys_call_ptr_t)custom_newstat;
#endif
#ifdef __NR_newlstat
    sys_call_table[__NR_newlstat] = (sys_call_ptr_t)custom_newlstat;
#endif
#ifdef __NR_newfstat
    sys_call_table[__NR_newfstat] = (sys_call_ptr_t)custom_newfstat;
#endif
#ifdef __NR_ustat
    sys_call_table[__NR_ustat] = (sys_call_ptr_t)custom_ustat;
#endif
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef __NR_stat64
    sys_call_table[__NR_stat64] = (sys_call_ptr_t)custom_stat64;
#endif
#ifdef __NR_fstat64
    sys_call_table[__NR_fstat64] = (sys_call_ptr_t)custom_fstat64;
#endif
#ifdef __NR_lstat64
    sys_call_table[__NR_lstat64] = (sys_call_ptr_t)custom_lstat64;
#endif
#ifdef __NR_fstatat64
    sys_call_table[__NR_fstatat64] = (sys_call_ptr_t)custom_fstatat64;
#endif
#endif
#if BITS_PER_LONG == 32
#ifdef __NR_truncate64
    sys_call_table[__NR_truncate64] = (sys_call_ptr_t)custom_truncate64;
#endif
#ifdef __NR_ftruncate64
    sys_call_table[__NR_ftruncate64] = (sys_call_ptr_t)custom_ftruncate64;
#endif
#endif

#ifdef __NR_setxattr
    sys_call_table[__NR_setxattr] = (sys_call_ptr_t)custom_setxattr;
#endif
#ifdef __NR_lsetxattr
    sys_call_table[__NR_lsetxattr] = (sys_call_ptr_t)custom_lsetxattr;
#endif
#ifdef __NR_fsetxattr
    sys_call_table[__NR_fsetxattr] = (sys_call_ptr_t)custom_fsetxattr;
#endif
#ifdef __NR_getxattr
    sys_call_table[__NR_getxattr] = (sys_call_ptr_t)custom_getxattr;
#endif
#ifdef __NR_lgetxattr
    sys_call_table[__NR_lgetxattr] = (sys_call_ptr_t)custom_lgetxattr;
#endif
#ifdef __NR_fgetxattr
    sys_call_table[__NR_fgetxattr] = (sys_call_ptr_t)custom_fgetxattr;
#endif
#ifdef __NR_listxattr
    sys_call_table[__NR_listxattr] = (sys_call_ptr_t)custom_listxattr;
#endif
#ifdef __NR_llistxattr
    sys_call_table[__NR_llistxattr] = (sys_call_ptr_t)custom_llistxattr;
#endif
#ifdef __NR_flistxattr
    sys_call_table[__NR_flistxattr] = (sys_call_ptr_t)custom_flistxattr;
#endif
#ifdef __NR_removexattr
    sys_call_table[__NR_removexattr] = (sys_call_ptr_t)custom_removexattr;
#endif
#ifdef __NR_lremovexattr
    sys_call_table[__NR_lremovexattr] = (sys_call_ptr_t)custom_lremovexattr;
#endif
#ifdef __NR_fremovexattr
    sys_call_table[__NR_fremovexattr] = (sys_call_ptr_t)custom_fremovexattr;
#endif

#ifdef __NR_brk
    sys_call_table[__NR_brk] = (sys_call_ptr_t)custom_brk;
#endif
#ifdef __NR_mprotect
    sys_call_table[__NR_mprotect] = (sys_call_ptr_t)custom_mprotect;
#endif
#ifdef __NR_mremap
    sys_call_table[__NR_mremap] = (sys_call_ptr_t)custom_mremap;
#endif
#ifdef __NR_remap_file_pages
    sys_call_table[__NR_remap_file_pages] = (sys_call_ptr_t)custom_remap_file_pages;
#endif
#ifdef __NR_msync
    sys_call_table[__NR_msync] = (sys_call_ptr_t)custom_msync;
#endif
#ifdef __NR_fadvise64
    sys_call_table[__NR_fadvise64] = (sys_call_ptr_t)custom_fadvise64;
#endif
#ifdef __NR_fadvise64_64
    sys_call_table[__NR_fadvise64_64] = (sys_call_ptr_t)custom_fadvise64_64;
#endif
#ifdef __NR_munmap
    sys_call_table[__NR_munmap] = (sys_call_ptr_t)custom_munmap;
#endif
#ifdef __NR_mlock
    sys_call_table[__NR_mlock] = (sys_call_ptr_t)custom_mlock;
#endif
#ifdef __NR_munlock
    sys_call_table[__NR_munlock] = (sys_call_ptr_t)custom_munlock;
#endif
#ifdef __NR_mlockall
    sys_call_table[__NR_mlockall] = (sys_call_ptr_t)custom_mlockall;
#endif
#ifdef __NR_munlockall
    sys_call_table[__NR_munlockall] = (sys_call_ptr_t)custom_munlockall;
#endif
#ifdef __NR_madvise
    sys_call_table[__NR_madvise] = (sys_call_ptr_t)custom_madvise;
#endif
#ifdef __NR_mincore
    sys_call_table[__NR_mincore] = (sys_call_ptr_t)custom_mincore;
#endif

#ifdef __NR_pivot_root
    sys_call_table[__NR_pivot_root] = (sys_call_ptr_t)custom_pivot_root;
#endif
#ifdef __NR_chroot
    sys_call_table[__NR_chroot] = (sys_call_ptr_t)custom_chroot;
#endif
#ifdef __NR_mknod
    sys_call_table[__NR_mknod] = (sys_call_ptr_t)custom_mknod;
#endif
#ifdef __NR_link
    sys_call_table[__NR_link] = (sys_call_ptr_t)custom_link;
#endif
#ifdef __NR_symlink
    sys_call_table[__NR_symlink] = (sys_call_ptr_t)custom_symlink;
#endif
#ifdef __NR_unlink
    sys_call_table[__NR_unlink] = (sys_call_ptr_t)custom_unlink;
#endif
#ifdef __NR_rename
    sys_call_table[__NR_rename] = (sys_call_ptr_t)custom_rename;
#endif
#ifdef __NR_chmod
    sys_call_table[__NR_chmod] = (sys_call_ptr_t)custom_chmod;
#endif
#ifdef __NR_fchmod
    sys_call_table[__NR_fchmod] = (sys_call_ptr_t)custom_fchmod;
#endif

#ifdef __NR_fcntl
    sys_call_table[__NR_fcntl] = (sys_call_ptr_t)custom_fcntl;
#endif
#if BITS_PER_LONG == 32
#ifdef __NR_fcntl64
    sys_call_table[__NR_fcntl64] = (sys_call_ptr_t)custom_fcntl64;
#endif
#endif
#ifdef __NR_pipe
    sys_call_table[__NR_pipe] = (sys_call_ptr_t)custom_pipe;
#endif
#ifdef __NR_pipe2
    sys_call_table[__NR_pipe2] = (sys_call_ptr_t)custom_pipe2;
#endif
#ifdef __NR_dup
    sys_call_table[__NR_dup] = (sys_call_ptr_t)custom_dup;
#endif
#ifdef __NR_dup2
    sys_call_table[__NR_dup2] = (sys_call_ptr_t)custom_dup2;
#endif
#ifdef __NR_dup3
    sys_call_table[__NR_dup3] = (sys_call_ptr_t)custom_dup3;
#endif
#ifdef __NR_ioperm
    sys_call_table[__NR_ioperm] = (sys_call_ptr_t)custom_ioperm;
#endif
#ifdef __NR_ioctl
    sys_call_table[__NR_ioctl] = (sys_call_ptr_t)custom_ioctl;
#endif
#ifdef __NR_flock
    sys_call_table[__NR_flock] = (sys_call_ptr_t)custom_flock;
#endif
#ifdef __NR_io_setup
    sys_call_table[__NR_io_setup] = (sys_call_ptr_t)custom_io_setup;
#endif
#ifdef __NR_io_destroy
    sys_call_table[__NR_io_destroy] = (sys_call_ptr_t)custom_io_destroy;
#endif
#ifdef __NR_io_getevents
    sys_call_table[__NR_io_getevents] = (sys_call_ptr_t)custom_io_getevents;
#endif
#ifdef __NR_io_submit
    sys_call_table[__NR_io_submit] = (sys_call_ptr_t)custom_io_submit;
#endif
#ifdef __NR_io_cancel
    sys_call_table[__NR_io_cancel] = (sys_call_ptr_t)custom_io_cancel;
#endif
#ifdef __NR_sendfile
    sys_call_table[__NR_sendfile] = (sys_call_ptr_t)custom_sendfile;
#endif
#ifdef __NR_sendfile64
    sys_call_table[__NR_sendfile64] = (sys_call_ptr_t)custom_sendfile64;
#endif
#ifdef __NR_readlink
    sys_call_table[__NR_readlink] = (sys_call_ptr_t)custom_readlink;
#endif
#ifdef __NR_creat
    sys_call_table[__NR_creat] = (sys_call_ptr_t)custom_creat;
#endif
#ifdef __NR_open
    sys_call_table[__NR_open] = (sys_call_ptr_t)custom_open;
#endif
#ifdef __NR_close
    sys_call_table[__NR_close] = (sys_call_ptr_t)custom_close;
#endif
#ifdef __NR_access
    sys_call_table[__NR_access] = (sys_call_ptr_t)custom_access;
#endif
#ifdef __NR_vhangup
    sys_call_table[__NR_vhangup] = (sys_call_ptr_t)custom_vhangup;
#endif
#ifdef __NR_chown
    sys_call_table[__NR_chown] = (sys_call_ptr_t)custom_chown;
#endif
#ifdef __NR_lchown
    sys_call_table[__NR_lchown] = (sys_call_ptr_t)custom_lchown;
#endif
#ifdef __NR_fchown
    sys_call_table[__NR_fchown] = (sys_call_ptr_t)custom_fchown;
#endif
#ifdef CONFIG_HAVE_UID16
#ifdef __NR_chown16
    sys_call_table[__NR_chown16] = (sys_call_ptr_t)custom_chown16;
#endif
#ifdef __NR_lchown16
    sys_call_table[__NR_lchown16] = (sys_call_ptr_t)custom_lchown16;
#endif
#ifdef __NR_fchown16
    sys_call_table[__NR_fchown16] = (sys_call_ptr_t)custom_fchown16;
#endif
#ifdef __NR_setregid16
    sys_call_table[__NR_setregid16] = (sys_call_ptr_t)custom_setregid16;
#endif
#ifdef __NR_setgid16
    sys_call_table[__NR_setgid16] = (sys_call_ptr_t)custom_setgid16;
#endif
#ifdef __NR_setreuid16
    sys_call_table[__NR_setreuid16] = (sys_call_ptr_t)custom_setreuid16;
#endif
#ifdef __NR_setuid16
    sys_call_table[__NR_setuid16] = (sys_call_ptr_t)custom_setuid16;
#endif
#ifdef __NR_setresuid16
    sys_call_table[__NR_setresuid16] = (sys_call_ptr_t)custom_setresuid16;
#endif
#ifdef __NR_getresuid16
    sys_call_table[__NR_getresuid16] = (sys_call_ptr_t)custom_getresuid16;
#endif
#ifdef __NR_setresgid16
    sys_call_table[__NR_setresgid16] = (sys_call_ptr_t)custom_setresgid16;
#endif
#ifdef __NR_getresgid16
    sys_call_table[__NR_getresgid16] = (sys_call_ptr_t)custom_getresgid16;
#endif
#ifdef __NR_setfsuid16
    sys_call_table[__NR_setfsuid16] = (sys_call_ptr_t)custom_setfsuid16;
#endif
#ifdef __NR_setfsgid16
    sys_call_table[__NR_setfsgid16] = (sys_call_ptr_t)custom_setfsgid16;
#endif
#ifdef __NR_getgroups16
    sys_call_table[__NR_getgroups16] = (sys_call_ptr_t)custom_getgroups16;
#endif
#ifdef __NR_setgroups16
    sys_call_table[__NR_setgroups16] = (sys_call_ptr_t)custom_setgroups16;
#endif
#ifdef __NR_getuid16
    sys_call_table[__NR_getuid16] = (sys_call_ptr_t)custom_getuid16;
#endif
#ifdef __NR_geteuid16
    sys_call_table[__NR_geteuid16] = (sys_call_ptr_t)custom_geteuid16;
#endif
#ifdef __NR_getgid16
    sys_call_table[__NR_getgid16] = (sys_call_ptr_t)custom_getgid16;
#endif
#ifdef __NR_getegid16
    sys_call_table[__NR_getegid16] = (sys_call_ptr_t)custom_getegid16;
#endif
#endif

#ifdef __NR_utime
    sys_call_table[__NR_utime] = (sys_call_ptr_t)custom_utime;
#endif
#ifdef __NR_utimes
    sys_call_table[__NR_utimes] = (sys_call_ptr_t)custom_utimes;
#endif
#ifdef __NR_lseek
    sys_call_table[__NR_lseek] = (sys_call_ptr_t)custom_lseek;
#endif
#ifdef __NR_llseek
    sys_call_table[__NR_llseek] = (sys_call_ptr_t)custom_llseek;
#endif
#ifdef __NR_read
    sys_call_table[__NR_read] = (sys_call_ptr_t)custom_read;
#endif
#ifdef __NR_readahead
    sys_call_table[__NR_readahead] = (sys_call_ptr_t)custom_readahead;
#endif
#ifdef __NR_readv
    sys_call_table[__NR_readv] = (sys_call_ptr_t)custom_readv;
#endif
#ifdef __NR_write
    sys_call_table[__NR_write] = (sys_call_ptr_t)custom_write;
#endif
#ifdef __NR_writev
    sys_call_table[__NR_writev] = (sys_call_ptr_t)custom_writev;
#endif
#ifdef __NR_pread64
    sys_call_table[__NR_pread64] = (sys_call_ptr_t)custom_pread64;
#endif
#ifdef __NR_pwrite64
    sys_call_table[__NR_pwrite64] = (sys_call_ptr_t)custom_pwrite64;
#endif
#ifdef __NR_preadv
    sys_call_table[__NR_preadv] = (sys_call_ptr_t)custom_preadv;
#endif
#ifdef __NR_preadv2
    sys_call_table[__NR_preadv2] = (sys_call_ptr_t)custom_preadv2;
#endif
#ifdef __NR_pwritev
    sys_call_table[__NR_pwritev] = (sys_call_ptr_t)custom_pwritev;
#endif
#ifdef __NR_pwritev2
    sys_call_table[__NR_pwritev2] = (sys_call_ptr_t)custom_pwritev2;
#endif
#ifdef __NR_getcwd
    sys_call_table[__NR_getcwd] = (sys_call_ptr_t)custom_getcwd;
#endif
#ifdef __NR_mkdir
    sys_call_table[__NR_mkdir] = (sys_call_ptr_t)custom_mkdir;
#endif
#ifdef __NR_chdir
    sys_call_table[__NR_chdir] = (sys_call_ptr_t)custom_chdir;
#endif
#ifdef __NR_fchdir
    sys_call_table[__NR_fchdir] = (sys_call_ptr_t)custom_fchdir;
#endif
#ifdef __NR_rmdir
    sys_call_table[__NR_rmdir] = (sys_call_ptr_t)custom_rmdir;
#endif
#ifdef __NR_lookup_dcookie
    sys_call_table[__NR_lookup_dcookie] = (sys_call_ptr_t)custom_lookup_dcookie;
#endif
#ifdef __NR_quotactl
    sys_call_table[__NR_quotactl] = (sys_call_ptr_t)custom_quotactl;
#endif
#ifdef __NR_getdents
    sys_call_table[__NR_getdents] = (sys_call_ptr_t)custom_getdents;
#endif
#ifdef __NR_getdents64
    sys_call_table[__NR_getdents64] = (sys_call_ptr_t)custom_getdents64;
#endif

#ifdef __NR_setsockopt
    sys_call_table[__NR_setsockopt] = (sys_call_ptr_t)custom_setsockopt;
#endif
#ifdef __NR_getsockopt
    sys_call_table[__NR_getsockopt] = (sys_call_ptr_t)custom_getsockopt;
#endif
#ifdef __NR_bind
    sys_call_table[__NR_bind] = (sys_call_ptr_t)custom_bind;
#endif
#ifdef __NR_connect
    sys_call_table[__NR_connect] = (sys_call_ptr_t)custom_connect;
#endif
#ifdef __NR_accept
    sys_call_table[__NR_accept] = (sys_call_ptr_t)custom_accept;
#endif
#ifdef __NR_accept4
    sys_call_table[__NR_accept4] = (sys_call_ptr_t)custom_accept4;
#endif
#ifdef __NR_getsockname
    sys_call_table[__NR_getsockname] = (sys_call_ptr_t)custom_getsockname;
#endif
#ifdef __NR_getpeername
    sys_call_table[__NR_getpeername] = (sys_call_ptr_t)custom_getpeername;
#endif
#ifdef __NR_send
    sys_call_table[__NR_send] = (sys_call_ptr_t)custom_send;
#endif
#ifdef __NR_sendto
    sys_call_table[__NR_sendto] = (sys_call_ptr_t)custom_sendto;
#endif
#ifdef __NR_sendmsg
    sys_call_table[__NR_sendmsg] = (sys_call_ptr_t)custom_sendmsg;
#endif
#ifdef __NR_sendmmsg
    sys_call_table[__NR_sendmmsg] = (sys_call_ptr_t)custom_sendmmsg;
#endif
#ifdef __NR_recv
    sys_call_table[__NR_recv] = (sys_call_ptr_t)custom_recv;
#endif
#ifdef __NR_recvfrom
    sys_call_table[__NR_recvfrom] = (sys_call_ptr_t)custom_recvfrom;
#endif
#ifdef __NR_recvmsg
    sys_call_table[__NR_recvmsg] = (sys_call_ptr_t)custom_recvmsg;
#endif
#ifdef __NR_recvmmsg
    sys_call_table[__NR_recvmmsg] = (sys_call_ptr_t)custom_recvmmsg;
#endif
#ifdef __NR_socket
    sys_call_table[__NR_socket] = (sys_call_ptr_t)custom_socket;
#endif
#ifdef __NR_socketpair
    sys_call_table[__NR_socketpair] = (sys_call_ptr_t)custom_socketpair;
#endif
#ifdef __NR_socketcall
    sys_call_table[__NR_socketcall] = (sys_call_ptr_t)custom_socketcall;
#endif
#ifdef __NR_listen
    sys_call_table[__NR_listen] = (sys_call_ptr_t)custom_listen;
#endif
#ifdef __NR_poll
    sys_call_table[__NR_poll] = (sys_call_ptr_t)custom_poll;
#endif
#ifdef __NR_select
    sys_call_table[__NR_select] = (sys_call_ptr_t)custom_select;
#endif
#ifdef __NR_old_select
    sys_call_table[__NR_old_select] = (sys_call_ptr_t)custom_old_select;
#endif
#ifdef __NR_epoll_create
    sys_call_table[__NR_epoll_create] = (sys_call_ptr_t)custom_epoll_create;
#endif
#ifdef __NR_epoll_create1
    sys_call_table[__NR_epoll_create1] = (sys_call_ptr_t)custom_epoll_create1;
#endif
#ifdef __NR_epoll_ctl
    sys_call_table[__NR_epoll_ctl] = (sys_call_ptr_t)custom_epoll_ctl;
#endif
#ifdef __NR_epoll_wait
    sys_call_table[__NR_epoll_wait] = (sys_call_ptr_t)custom_epoll_wait;
#endif
#ifdef __NR_epoll_pwait
    sys_call_table[__NR_epoll_pwait] = (sys_call_ptr_t)custom_epoll_pwait;
#endif
#ifdef __NR_gethostname
    sys_call_table[__NR_gethostname] = (sys_call_ptr_t)custom_gethostname;
#endif
#ifdef __NR_sethostname
    sys_call_table[__NR_sethostname] = (sys_call_ptr_t)custom_sethostname;
#endif
#ifdef __NR_setdomainname
    sys_call_table[__NR_setdomainname] = (sys_call_ptr_t)custom_setdomainname;
#endif
#ifdef __NR_newuname
    sys_call_table[__NR_newuname] = (sys_call_ptr_t)custom_newuname;
#endif
#ifdef __NR_uname
    sys_call_table[__NR_uname] = (sys_call_ptr_t)custom_uname;
#endif
#ifdef __NR_olduname
    sys_call_table[__NR_olduname] = (sys_call_ptr_t)custom_olduname;
#endif

#ifdef __NR_getrlimit
    sys_call_table[__NR_getrlimit] = (sys_call_ptr_t)custom_getrlimit;
#endif
#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT
#ifdef __NR_old_getrlimit
    sys_call_table[__NR_old_getrlimit] = (sys_call_ptr_t)custom_old_getrlimit;
#endif
#endif
#ifdef __NR_setrlimit
    sys_call_table[__NR_setrlimit] = (sys_call_ptr_t)custom_setrlimit;
#endif
#ifdef __NR_prlimit64
    sys_call_table[__NR_prlimit64] = (sys_call_ptr_t)custom_prlimit64;
#endif
#ifdef __NR_getrusage
    sys_call_table[__NR_getrusage] = (sys_call_ptr_t)custom_getrusage;
#endif
#ifdef __NR_umask
    sys_call_table[__NR_umask] = (sys_call_ptr_t)custom_umask;
#endif

#ifdef __NR_msgget
    sys_call_table[__NR_msgget] = (sys_call_ptr_t)custom_msgget;
#endif
#ifdef __NR_msgsnd
    sys_call_table[__NR_msgsnd] = (sys_call_ptr_t)custom_msgsnd;
#endif
#ifdef __NR_msgrcv
    sys_call_table[__NR_msgrcv] = (sys_call_ptr_t)custom_msgrcv;
#endif
#ifdef __NR_msgctl
    sys_call_table[__NR_msgctl] = (sys_call_ptr_t)custom_msgctl;
#endif

#ifdef __NR_semget
    sys_call_table[__NR_semget] = (sys_call_ptr_t)custom_semget;
#endif
#ifdef __NR_semop
    sys_call_table[__NR_semop] = (sys_call_ptr_t)custom_semop;
#endif
#ifdef __NR_semctl
    sys_call_table[__NR_semctl] = (sys_call_ptr_t)custom_semctl;
#endif
#ifdef __NR_semtimedop
    sys_call_table[__NR_semtimedop] = (sys_call_ptr_t)custom_semtimedop;
#endif
#ifdef __NR_shmat
    sys_call_table[__NR_shmat] = (sys_call_ptr_t)custom_shmat;
#endif
#ifdef __NR_shmget
    sys_call_table[__NR_shmget] = (sys_call_ptr_t)custom_shmget;
#endif
#ifdef __NR_shmdt
    sys_call_table[__NR_shmdt] = (sys_call_ptr_t)custom_shmdt;
#endif
#ifdef __NR_shmctl
    sys_call_table[__NR_shmctl] = (sys_call_ptr_t)custom_shmctl;
#endif
#ifdef __NR_ipc
    sys_call_table[__NR_ipc] = (sys_call_ptr_t)custom_ipc;
#endif

#ifdef __NR_mq_open
    sys_call_table[__NR_mq_open] = (sys_call_ptr_t)custom_mq_open;
#endif
#ifdef __NR_mq_unlink
    sys_call_table[__NR_mq_unlink] = (sys_call_ptr_t)custom_mq_unlink;
#endif
#ifdef __NR_mq_timedsend
    sys_call_table[__NR_mq_timedsend] = (sys_call_ptr_t)custom_mq_timedsend;
#endif
#ifdef __NR_mq_timedreceive
    sys_call_table[__NR_mq_timedreceive] = (sys_call_ptr_t)custom_mq_timedreceive;
#endif
#ifdef __NR_mq_notify
    sys_call_table[__NR_mq_notify] = (sys_call_ptr_t)custom_mq_notify;
#endif
#ifdef __NR_mq_getsetattr
    sys_call_table[__NR_mq_getsetattr] = (sys_call_ptr_t)custom_mq_getsetattr;
#endif

#ifdef __NR_pciconfig_iobase
    sys_call_table[__NR_pciconfig_iobase] = (sys_call_ptr_t)custom_pciconfig_iobase;
#endif
#ifdef __NR_pciconfig_read
    sys_call_table[__NR_pciconfig_read] = (sys_call_ptr_t)custom_pciconfig_read;
#endif
#ifdef __NR_pciconfig_write
    sys_call_table[__NR_pciconfig_write] = (sys_call_ptr_t)custom_pciconfig_write;
#endif

#ifdef __NR_prctl
    sys_call_table[__NR_prctl] = (sys_call_ptr_t)custom_prctl;
#endif
#ifdef __NR_swapon
    sys_call_table[__NR_swapon] = (sys_call_ptr_t)custom_swapon;
#endif
#ifdef __NR_swapoff
    sys_call_table[__NR_swapoff] = (sys_call_ptr_t)custom_swapoff;
#endif
#ifdef __NR_sysctl
    sys_call_table[__NR_sysctl] = (sys_call_ptr_t)custom_sysctl;
#endif
#ifdef __NR_sysinfo
    sys_call_table[__NR_sysinfo] = (sys_call_ptr_t)custom_sysinfo;
#endif
#ifdef __NR_sysfs
    sys_call_table[__NR_sysfs] = (sys_call_ptr_t)custom_sysfs;
#endif
#ifdef __NR_syslog
    sys_call_table[__NR_syslog] = (sys_call_ptr_t)custom_syslog;
#endif
#ifdef __NR_uselib
    sys_call_table[__NR_uselib] = (sys_call_ptr_t)custom_uselib;
#endif
#ifdef __NR_ni_syscall
    sys_call_table[__NR_ni_syscall] = (sys_call_ptr_t)custom_ni_syscall;
#endif
#ifdef __NR_ptrace
    sys_call_table[__NR_ptrace] = (sys_call_ptr_t)custom_ptrace;
#endif

#ifdef __NR_add_key
    sys_call_table[__NR_add_key] = (sys_call_ptr_t)custom_add_key;
#endif

#ifdef __NR_request_key
    sys_call_table[__NR_request_key] = (sys_call_ptr_t)custom_request_key;
#endif

#ifdef __NR_keyctl
    sys_call_table[__NR_keyctl] = (sys_call_ptr_t)custom_keyctl;
#endif

#ifdef __NR_ioprio_set
    sys_call_table[__NR_ioprio_set] = (sys_call_ptr_t)custom_ioprio_set;
#endif
#ifdef __NR_ioprio_get
    sys_call_table[__NR_ioprio_get] = (sys_call_ptr_t)custom_ioprio_get;
#endif
#ifdef __NR_set_mempolicy
    sys_call_table[__NR_set_mempolicy] = (sys_call_ptr_t)custom_set_mempolicy;
#endif
#ifdef __NR_migrate_pages
    sys_call_table[__NR_migrate_pages] = (sys_call_ptr_t)custom_migrate_pages;
#endif
#ifdef __NR_move_pages
    sys_call_table[__NR_move_pages] = (sys_call_ptr_t)custom_move_pages;
#endif
#ifdef __NR_mbind
    sys_call_table[__NR_mbind] = (sys_call_ptr_t)custom_mbind;
#endif
#ifdef __NR_get_mempolicy
    sys_call_table[__NR_get_mempolicy] = (sys_call_ptr_t)custom_get_mempolicy;
#endif

#ifdef __NR_inotify_init
    sys_call_table[__NR_inotify_init] = (sys_call_ptr_t)custom_inotify_init;
#endif
#ifdef __NR_inotify_init1
    sys_call_table[__NR_inotify_init1] = (sys_call_ptr_t)custom_inotify_init1;
#endif
#ifdef __NR_inotify_add_watch
    sys_call_table[__NR_inotify_add_watch] = (sys_call_ptr_t)custom_inotify_add_watch;
#endif
#ifdef __NR_inotify_rm_watch
    sys_call_table[__NR_inotify_rm_watch] = (sys_call_ptr_t)custom_inotify_rm_watch;
#endif

#ifdef __NR_spu_run
    sys_call_table[__NR_spu_run] = (sys_call_ptr_t)custom_spu_run;
#endif
#ifdef __NR_spu_create
    sys_call_table[__NR_spu_create] = (sys_call_ptr_t)custom_spu_create;
#endif

#ifdef __NR_mknodat
    sys_call_table[__NR_mknodat] = (sys_call_ptr_t)custom_mknodat;
#endif
#ifdef __NR_mkdirat
    sys_call_table[__NR_mkdirat] = (sys_call_ptr_t)custom_mkdirat;
#endif
#ifdef __NR_unlinkat
    sys_call_table[__NR_unlinkat] = (sys_call_ptr_t)custom_unlinkat;
#endif
#ifdef __NR_symlinkat
    sys_call_table[__NR_symlinkat] = (sys_call_ptr_t)custom_symlinkat;
#endif
#ifdef __NR_linkat
    sys_call_table[__NR_linkat] = (sys_call_ptr_t)custom_linkat;
#endif
#ifdef __NR_renameat
    sys_call_table[__NR_renameat] = (sys_call_ptr_t)custom_renameat;
#endif
#ifdef __NR_renameat2
    sys_call_table[__NR_renameat2] = (sys_call_ptr_t)custom_renameat2;
#endif
#ifdef __NR_futimesat
    sys_call_table[__NR_futimesat] = (sys_call_ptr_t)custom_futimesat;
#endif
#ifdef __NR_faccessat
    sys_call_table[__NR_faccessat] = (sys_call_ptr_t)custom_faccessat;
#endif
#ifdef __NR_fchmodat
    sys_call_table[__NR_fchmodat] = (sys_call_ptr_t)custom_fchmodat;
#endif
#ifdef __NR_fchownat
    sys_call_table[__NR_fchownat] = (sys_call_ptr_t)custom_fchownat;
#endif
#ifdef __NR_openat
    sys_call_table[__NR_openat] = (sys_call_ptr_t)custom_openat;
#endif
#ifdef __NR_newfstatat
    sys_call_table[__NR_newfstatat] = (sys_call_ptr_t)custom_newfstatat;
#endif
#ifdef __NR_readlinkat
    sys_call_table[__NR_readlinkat] = (sys_call_ptr_t)custom_readlinkat;
#endif
#ifdef __NR_utimensat
    sys_call_table[__NR_utimensat] = (sys_call_ptr_t)custom_utimensat;
#endif
#ifdef __NR_unshare
    sys_call_table[__NR_unshare] = (sys_call_ptr_t)custom_unshare;
#endif

#ifdef __NR_splice
    sys_call_table[__NR_splice] = (sys_call_ptr_t)custom_splice;
#endif

#ifdef __NR_vmsplice
    sys_call_table[__NR_vmsplice] = (sys_call_ptr_t)custom_vmsplice;
#endif

#ifdef __NR_tee
    sys_call_table[__NR_tee] = (sys_call_ptr_t)custom_tee;
#endif

#ifdef __NR_sync_file_range
    sys_call_table[__NR_sync_file_range] = (sys_call_ptr_t)custom_sync_file_range;
#endif
#ifdef __NR_sync_file_range2
    sys_call_table[__NR_sync_file_range2] = (sys_call_ptr_t)custom_sync_file_range2;
#endif
#ifdef __NR_get_robust_list
    sys_call_table[__NR_get_robust_list] = (sys_call_ptr_t)custom_get_robust_list;
#endif
#ifdef __NR_set_robust_list
    sys_call_table[__NR_set_robust_list] = (sys_call_ptr_t)custom_set_robust_list;
#endif
#ifdef __NR_getcpu
    sys_call_table[__NR_getcpu] = (sys_call_ptr_t)custom_getcpu;
#endif
#ifdef __NR_signalfd
    sys_call_table[__NR_signalfd] = (sys_call_ptr_t)custom_signalfd;
#endif
#ifdef __NR_signalfd4
    sys_call_table[__NR_signalfd4] = (sys_call_ptr_t)custom_signalfd4;
#endif
#ifdef __NR_timerfd_create
    sys_call_table[__NR_timerfd_create] = (sys_call_ptr_t)custom_timerfd_create;
#endif
#ifdef __NR_timerfd_settime
    sys_call_table[__NR_timerfd_settime] = (sys_call_ptr_t)custom_timerfd_settime;
#endif
#ifdef __NR_timerfd_gettime
    sys_call_table[__NR_timerfd_gettime] = (sys_call_ptr_t)custom_timerfd_gettime;
#endif
#ifdef __NR_eventfd
    sys_call_table[__NR_eventfd] = (sys_call_ptr_t)custom_eventfd;
#endif
#ifdef __NR_eventfd2
    sys_call_table[__NR_eventfd2] = (sys_call_ptr_t)custom_eventfd2;
#endif
#ifdef __NR_memfd_create
    sys_call_table[__NR_memfd_create] = (sys_call_ptr_t)custom_memfd_create;
#endif
#ifdef __NR_userfaultfd
    sys_call_table[__NR_userfaultfd] = (sys_call_ptr_t)custom_userfaultfd;
#endif
#ifdef __NR_fallocate
    sys_call_table[__NR_fallocate] = (sys_call_ptr_t)custom_fallocate;
#endif
#ifdef __NR_old_readdir
    sys_call_table[__NR_old_readdir] = (sys_call_ptr_t)custom_old_readdir;
#endif
#ifdef __NR_pselect6
    sys_call_table[__NR_pselect6] = (sys_call_ptr_t)custom_pselect6;
#endif
#ifdef __NR_ppoll
    sys_call_table[__NR_ppoll] = (sys_call_ptr_t)custom_ppoll;
#endif
#ifdef __NR_fanotify_init
    sys_call_table[__NR_fanotify_init] = (sys_call_ptr_t)custom_fanotify_init;
#endif
#ifdef __NR_fanotify_mark
    sys_call_table[__NR_fanotify_mark] = (sys_call_ptr_t)custom_fanotify_mark;
#endif
#ifdef __NR_syncfs
    sys_call_table[__NR_syncfs] = (sys_call_ptr_t)custom_syncfs;
#endif

#ifdef __NR_fork
    sys_call_table[__NR_fork] = (sys_call_ptr_t)custom_fork;
#endif
#ifdef __NR_vfork
    sys_call_table[__NR_vfork] = (sys_call_ptr_t)custom_vfork;
#endif
#ifdef CONFIG_CLONE_BACKWARDS
#ifdef __NR_clone
    sys_call_table[__NR_clone] = (sys_call_ptr_t)custom_clone;
#endif
#else
#ifdef CONFIG_CLONE_BACKWARDS3
#ifdef __NR_clone
    sys_call_table[__NR_clone] = (sys_call_ptr_t)custom_clone;
#endif
#else
#ifdef __NR_clone
    sys_call_table[__NR_clone] = (sys_call_ptr_t)custom_clone;
#endif
#endif
#endif

#ifdef __NR_execve
    sys_call_table[__NR_execve] = (sys_call_ptr_t)custom_execve;
#endif

#ifdef __NR_perf_event_open
    sys_call_table[__NR_perf_event_open] = (sys_call_ptr_t)custom_perf_event_open;
#endif

#ifdef __NR_mmap_pgoff
    sys_call_table[__NR_mmap_pgoff] = (sys_call_ptr_t)custom_mmap_pgoff;
#endif
#ifdef __NR_old_mmap
    sys_call_table[__NR_old_mmap] = (sys_call_ptr_t)custom_old_mmap;
#endif
#ifdef __NR_name_to_handle_at
    sys_call_table[__NR_name_to_handle_at] = (sys_call_ptr_t)custom_name_to_handle_at;
#endif
#ifdef __NR_open_by_handle_at
    sys_call_table[__NR_open_by_handle_at] = (sys_call_ptr_t)custom_open_by_handle_at;
#endif
#ifdef __NR_setns
    sys_call_table[__NR_setns] = (sys_call_ptr_t)custom_setns;
#endif
#ifdef __NR_process_vm_readv
    sys_call_table[__NR_process_vm_readv] = (sys_call_ptr_t)custom_process_vm_readv;
#endif
#ifdef __NR_process_vm_writev
    sys_call_table[__NR_process_vm_writev] = (sys_call_ptr_t)custom_process_vm_writev;
#endif

#ifdef __NR_kcmp
    sys_call_table[__NR_kcmp] = (sys_call_ptr_t)custom_kcmp;
#endif
#ifdef __NR_finit_module
    sys_call_table[__NR_finit_module] = (sys_call_ptr_t)custom_finit_module;
#endif
#ifdef __NR_seccomp
    sys_call_table[__NR_seccomp] = (sys_call_ptr_t)custom_seccomp;
#endif
#ifdef __NR_getrandom
    sys_call_table[__NR_getrandom] = (sys_call_ptr_t)custom_getrandom;
#endif
#ifdef __NR_bpf
    sys_call_table[__NR_bpf] = (sys_call_ptr_t)custom_bpf;
#endif

#ifdef __NR_execveat
    sys_call_table[__NR_execveat] = (sys_call_ptr_t)custom_execveat;
#endif

#ifdef __NR_membarrier
    sys_call_table[__NR_membarrier] = (sys_call_ptr_t)custom_membarrier;
#endif
#ifdef __NR_copy_file_range
    sys_call_table[__NR_copy_file_range] = (sys_call_ptr_t)custom_copy_file_range;
#endif

#ifdef __NR_mlock2
    sys_call_table[__NR_mlock2] = (sys_call_ptr_t)custom_mlock2;
#endif

#ifdef __NR_pkey_mprotect
    sys_call_table[__NR_pkey_mprotect] = (sys_call_ptr_t)custom_pkey_mprotect;
#endif
#ifdef __NR_pkey_alloc
    sys_call_table[__NR_pkey_alloc] = (sys_call_ptr_t)custom_pkey_alloc;
#endif
#ifdef __NR_pkey_free
    sys_call_table[__NR_pkey_free] = (sys_call_ptr_t)custom_pkey_free;
#endif
#ifdef __NR_statx
    sys_call_table[__NR_statx] = (sys_call_ptr_t)custom_statx;
#endif

    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);

    return 0;
}

static void __exit hello_exit(void)
{
    printk(KERN_ALERT "ISOLATES:Custom FileOps module removed successfully\n");

// Reassigning the original syscall table entries to point to original syscall functions
    
    // Temporarily disable write protection
    write_cr0(read_cr0() & (~0x10000));

#ifdef __NR_time
    sys_call_table[__NR_time] = org_sys_table[__NR_time];
#endif
#ifdef __NR_stime
    sys_call_table[__NR_stime] = org_sys_table[__NR_stime];
#endif
#ifdef __NR_gettimeofday
    sys_call_table[__NR_gettimeofday] = org_sys_table[__NR_gettimeofday];
#endif
#ifdef __NR_settimeofday
    sys_call_table[__NR_settimeofday] = org_sys_table[__NR_settimeofday];
#endif
#ifdef __NR_adjtimex
    sys_call_table[__NR_adjtimex] = org_sys_table[__NR_adjtimex];
#endif

#ifdef __NR_times
    sys_call_table[__NR_times] = org_sys_table[__NR_times];
#endif

#ifdef __NR_gettid
    sys_call_table[__NR_gettid] = org_sys_table[__NR_gettid];
#endif
#ifdef __NR_nanosleep
    sys_call_table[__NR_nanosleep] = org_sys_table[__NR_nanosleep];
#endif
#ifdef __NR_alarm
    sys_call_table[__NR_alarm] = org_sys_table[__NR_alarm];
#endif
#ifdef __NR_getpid
    sys_call_table[__NR_getpid] = org_sys_table[__NR_getpid];
#endif
#ifdef __NR_getppid
    sys_call_table[__NR_getppid] = org_sys_table[__NR_getppid];
#endif
#ifdef __NR_getuid
    sys_call_table[__NR_getuid] = org_sys_table[__NR_getuid];
#endif
#ifdef __NR_geteuid
    sys_call_table[__NR_geteuid] = org_sys_table[__NR_geteuid];
#endif
#ifdef __NR_getgid
    sys_call_table[__NR_getgid] = org_sys_table[__NR_getgid];
#endif
#ifdef __NR_getegid
    sys_call_table[__NR_getegid] = org_sys_table[__NR_getegid];
#endif
#ifdef __NR_getresuid
    sys_call_table[__NR_getresuid] = org_sys_table[__NR_getresuid];
#endif
#ifdef __NR_getresgid
    sys_call_table[__NR_getresgid] = org_sys_table[__NR_getresgid];
#endif
#ifdef __NR_getpgid
    sys_call_table[__NR_getpgid] = org_sys_table[__NR_getpgid];
#endif
#ifdef __NR_getpgrp
    sys_call_table[__NR_getpgrp] = org_sys_table[__NR_getpgrp];
#endif
#ifdef __NR_getsid
    sys_call_table[__NR_getsid] = org_sys_table[__NR_getsid];
#endif
#ifdef __NR_getgroups
    sys_call_table[__NR_getgroups] = org_sys_table[__NR_getgroups];
#endif

#ifdef __NR_setregid
    sys_call_table[__NR_setregid] = org_sys_table[__NR_setregid];
#endif
#ifdef __NR_setgid
    sys_call_table[__NR_setgid] = org_sys_table[__NR_setgid];
#endif
#ifdef __NR_setreuid
    sys_call_table[__NR_setreuid] = org_sys_table[__NR_setreuid];
#endif
#ifdef __NR_setuid
    sys_call_table[__NR_setuid] = org_sys_table[__NR_setuid];
#endif
#ifdef __NR_setresuid
    sys_call_table[__NR_setresuid] = org_sys_table[__NR_setresuid];
#endif
#ifdef __NR_setresgid
    sys_call_table[__NR_setresgid] = org_sys_table[__NR_setresgid];
#endif
#ifdef __NR_setfsuid
    sys_call_table[__NR_setfsuid] = org_sys_table[__NR_setfsuid];
#endif
#ifdef __NR_setfsgid
    sys_call_table[__NR_setfsgid] = org_sys_table[__NR_setfsgid];
#endif
#ifdef __NR_setpgid
    sys_call_table[__NR_setpgid] = org_sys_table[__NR_setpgid];
#endif
#ifdef __NR_setsid
    sys_call_table[__NR_setsid] = org_sys_table[__NR_setsid];
#endif
#ifdef __NR_setgroups
    sys_call_table[__NR_setgroups] = org_sys_table[__NR_setgroups];
#endif

#ifdef __NR_acct
    sys_call_table[__NR_acct] = org_sys_table[__NR_acct];
#endif
#ifdef __NR_capget
    sys_call_table[__NR_capget] = org_sys_table[__NR_capget];
#endif
#ifdef __NR_capset
    sys_call_table[__NR_capset] = org_sys_table[__NR_capset];
#endif
#ifdef __NR_personality
    sys_call_table[__NR_personality] = org_sys_table[__NR_personality];
#endif

#ifdef __NR_sigpending
    sys_call_table[__NR_sigpending] = org_sys_table[__NR_sigpending];
#endif
#ifdef __NR_sigprocmask
    sys_call_table[__NR_sigprocmask] = org_sys_table[__NR_sigprocmask];
#endif
#ifdef __NR_sigaltstack
    sys_call_table[__NR_sigaltstack] = org_sys_table[__NR_sigaltstack];
#endif

#ifdef __NR_getitimer
    sys_call_table[__NR_getitimer] = org_sys_table[__NR_getitimer];
#endif
#ifdef __NR_setitimer
    sys_call_table[__NR_setitimer] = org_sys_table[__NR_setitimer];
#endif
#ifdef __NR_timer_create
    sys_call_table[__NR_timer_create] = org_sys_table[__NR_timer_create];
#endif
#ifdef __NR_timer_gettime
    sys_call_table[__NR_timer_gettime] = org_sys_table[__NR_timer_gettime];
#endif
#ifdef __NR_timer_getoverrun
    sys_call_table[__NR_timer_getoverrun] = org_sys_table[__NR_timer_getoverrun];
#endif
#ifdef __NR_timer_settime
    sys_call_table[__NR_timer_settime] = org_sys_table[__NR_timer_settime];
#endif
#ifdef __NR_timer_delete
    sys_call_table[__NR_timer_delete] = org_sys_table[__NR_timer_delete];
#endif
#ifdef __NR_clock_settime
    sys_call_table[__NR_clock_settime] = org_sys_table[__NR_clock_settime];
#endif
#ifdef __NR_clock_gettime
    sys_call_table[__NR_clock_gettime] = org_sys_table[__NR_clock_gettime];
#endif
#ifdef __NR_clock_adjtime
    sys_call_table[__NR_clock_adjtime] = org_sys_table[__NR_clock_adjtime];
#endif
#ifdef __NR_clock_getres
    sys_call_table[__NR_clock_getres] = org_sys_table[__NR_clock_getres];
#endif
#ifdef __NR_clock_nanosleep
    sys_call_table[__NR_clock_nanosleep] = org_sys_table[__NR_clock_nanosleep];
#endif

#ifdef __NR_nice
    sys_call_table[__NR_nice] = org_sys_table[__NR_nice];
#endif
#ifdef __NR_sched_setscheduler
    sys_call_table[__NR_sched_setscheduler] = org_sys_table[__NR_sched_setscheduler];
#endif
#ifdef __NR_sched_setparam
    sys_call_table[__NR_sched_setparam] = org_sys_table[__NR_sched_setparam];
#endif
#ifdef __NR_sched_setattr
    sys_call_table[__NR_sched_setattr] = org_sys_table[__NR_sched_setattr];
#endif
#ifdef __NR_sched_getscheduler
    sys_call_table[__NR_sched_getscheduler] = org_sys_table[__NR_sched_getscheduler];
#endif
#ifdef __NR_sched_getparam
    sys_call_table[__NR_sched_getparam] = org_sys_table[__NR_sched_getparam];
#endif
#ifdef __NR_sched_getattr
    sys_call_table[__NR_sched_getattr] = org_sys_table[__NR_sched_getattr];
#endif
#ifdef __NR_sched_setaffinity
    sys_call_table[__NR_sched_setaffinity] = org_sys_table[__NR_sched_setaffinity];
#endif
#ifdef __NR_sched_getaffinity
    sys_call_table[__NR_sched_getaffinity] = org_sys_table[__NR_sched_getaffinity];
#endif
#ifdef __NR_sched_yield
    sys_call_table[__NR_sched_yield] = org_sys_table[__NR_sched_yield];
#endif
#ifdef __NR_sched_get_priority_max
    sys_call_table[__NR_sched_get_priority_max] = org_sys_table[__NR_sched_get_priority_max];
#endif
#ifdef __NR_sched_get_priority_min
    sys_call_table[__NR_sched_get_priority_min] = org_sys_table[__NR_sched_get_priority_min];
#endif
#ifdef __NR_sched_rr_get_interval
    sys_call_table[__NR_sched_rr_get_interval] = org_sys_table[__NR_sched_rr_get_interval];
#endif
#ifdef __NR_setpriority
    sys_call_table[__NR_setpriority] = org_sys_table[__NR_setpriority];
#endif
#ifdef __NR_getpriority
    sys_call_table[__NR_getpriority] = org_sys_table[__NR_getpriority];
#endif

#ifdef __NR_shutdown
    sys_call_table[__NR_shutdown] = org_sys_table[__NR_shutdown];
#endif
#ifdef __NR_reboot
    sys_call_table[__NR_reboot] = org_sys_table[__NR_reboot];
#endif
#ifdef __NR_restart_syscall
    sys_call_table[__NR_restart_syscall] = org_sys_table[__NR_restart_syscall];
#endif
#ifdef __NR_kexec_load
    sys_call_table[__NR_kexec_load] = org_sys_table[__NR_kexec_load];
#endif
#ifdef __NR_kexec_file_load
    sys_call_table[__NR_kexec_file_load] = org_sys_table[__NR_kexec_file_load];
#endif

#ifdef __NR_exit
    sys_call_table[__NR_exit] = org_sys_table[__NR_exit];
#endif
#ifdef __NR_exit_group
    sys_call_table[__NR_exit_group] = org_sys_table[__NR_exit_group];
#endif
#ifdef __NR_wait4
    sys_call_table[__NR_wait4] = org_sys_table[__NR_wait4];
#endif
#ifdef __NR_waitid
    sys_call_table[__NR_waitid] = org_sys_table[__NR_waitid];
#endif
#ifdef __NR_waitpid
    sys_call_table[__NR_waitpid] = org_sys_table[__NR_waitpid];
#endif
#ifdef __NR_set_tid_address
    sys_call_table[__NR_set_tid_address] = org_sys_table[__NR_set_tid_address];
#endif
#ifdef __NR_futex
    sys_call_table[__NR_futex] = org_sys_table[__NR_futex];
#endif

#ifdef __NR_init_module
    sys_call_table[__NR_init_module] = org_sys_table[__NR_init_module];
#endif
#ifdef __NR_delete_module
    sys_call_table[__NR_delete_module] = org_sys_table[__NR_delete_module];
#endif

#ifdef CONFIG_OLD_SIGSUSPEND
#ifdef __NR_sigsuspend
    sys_call_table[__NR_sigsuspend] = org_sys_table[__NR_sigsuspend];
#endif
#endif

#ifdef CONFIG_OLD_SIGSUSPEND3
#ifdef __NR_sigsuspend
    sys_call_table[__NR_sigsuspend] = org_sys_table[__NR_sigsuspend];
#endif
#endif

#ifdef __NR_rt_sigsuspend
    sys_call_table[__NR_rt_sigsuspend] = org_sys_table[__NR_rt_sigsuspend];
#endif

#ifdef CONFIG_OLD_SIGACTION
#ifdef __NR_sigaction
    sys_call_table[__NR_sigaction] = org_sys_table[__NR_sigaction];
#endif
#endif

#ifndef CONFIG_ODD_RT_SIGACTION
#ifdef __NR_rt_sigaction
    sys_call_table[__NR_rt_sigaction] = org_sys_table[__NR_rt_sigaction];
#endif
#endif
#ifdef __NR_rt_sigprocmask
    sys_call_table[__NR_rt_sigprocmask] = org_sys_table[__NR_rt_sigprocmask];
#endif
#ifdef __NR_rt_sigpending
    sys_call_table[__NR_rt_sigpending] = org_sys_table[__NR_rt_sigpending];
#endif
#ifdef __NR_rt_sigtimedwait
    sys_call_table[__NR_rt_sigtimedwait] = org_sys_table[__NR_rt_sigtimedwait];
#endif
#ifdef __NR_rt_tgsigqueueinfo
    sys_call_table[__NR_rt_tgsigqueueinfo] = org_sys_table[__NR_rt_tgsigqueueinfo];
#endif
#ifdef __NR_kill
    sys_call_table[__NR_kill] = org_sys_table[__NR_kill];
#endif
#ifdef __NR_tgkill
    sys_call_table[__NR_tgkill] = org_sys_table[__NR_tgkill];
#endif
#ifdef __NR_tkill
    sys_call_table[__NR_tkill] = org_sys_table[__NR_tkill];
#endif
#ifdef __NR_rt_sigqueueinfo
    sys_call_table[__NR_rt_sigqueueinfo] = org_sys_table[__NR_rt_sigqueueinfo];
#endif
#ifdef __NR_sgetmask
    sys_call_table[__NR_sgetmask] = org_sys_table[__NR_sgetmask];
#endif
#ifdef __NR_ssetmask
    sys_call_table[__NR_ssetmask] = org_sys_table[__NR_ssetmask];
#endif
#ifdef __NR_signal
    sys_call_table[__NR_signal] = org_sys_table[__NR_signal];
#endif
#ifdef __NR_pause
    sys_call_table[__NR_pause] = org_sys_table[__NR_pause];
#endif

#ifdef __NR_sync
    sys_call_table[__NR_sync] = org_sys_table[__NR_sync];
#endif
#ifdef __NR_fsync
    sys_call_table[__NR_fsync] = org_sys_table[__NR_fsync];
#endif
#ifdef __NR_fdatasync
    sys_call_table[__NR_fdatasync] = org_sys_table[__NR_fdatasync];
#endif
#ifdef __NR_bdflush
    sys_call_table[__NR_bdflush] = org_sys_table[__NR_bdflush];
#endif
#ifdef __NR_mount
    sys_call_table[__NR_mount] = org_sys_table[__NR_mount];
#endif
#ifdef __NR_umount
    sys_call_table[__NR_umount] = org_sys_table[__NR_umount];
#endif
#ifdef __NR_oldumount
    sys_call_table[__NR_oldumount] = org_sys_table[__NR_oldumount];
#endif
#ifdef __NR_truncate
    sys_call_table[__NR_truncate] = org_sys_table[__NR_truncate];
#endif
#ifdef __NR_ftruncate
    sys_call_table[__NR_ftruncate] = org_sys_table[__NR_ftruncate];
#endif
#ifdef __NR_stat
    sys_call_table[__NR_stat] = org_sys_table[__NR_stat];
#endif
#ifdef __NR_statfs
    sys_call_table[__NR_statfs] = org_sys_table[__NR_statfs];
#endif
#ifdef __NR_statfs64
    sys_call_table[__NR_statfs64] = org_sys_table[__NR_statfs64];
#endif
#ifdef __NR_fstatfs
    sys_call_table[__NR_fstatfs] = org_sys_table[__NR_fstatfs];
#endif
#ifdef __NR_fstatfs64
    sys_call_table[__NR_fstatfs64] = org_sys_table[__NR_fstatfs64];
#endif
#ifdef __NR_lstat
    sys_call_table[__NR_lstat] = org_sys_table[__NR_lstat];
#endif
#ifdef __NR_fstat
    sys_call_table[__NR_fstat] = org_sys_table[__NR_fstat];
#endif
#ifdef __NR_newstat
    sys_call_table[__NR_newstat] = org_sys_table[__NR_newstat];
#endif
#ifdef __NR_newlstat
    sys_call_table[__NR_newlstat] = org_sys_table[__NR_newlstat];
#endif
#ifdef __NR_newfstat
    sys_call_table[__NR_newfstat] = org_sys_table[__NR_newfstat];
#endif
#ifdef __NR_ustat
    sys_call_table[__NR_ustat] = org_sys_table[__NR_ustat];
#endif
#if defined(__ARCH_WANT_STAT64) || defined(__ARCH_WANT_COMPAT_STAT64)
#ifdef __NR_stat64
    sys_call_table[__NR_stat64] = org_sys_table[__NR_stat64];
#endif
#ifdef __NR_fstat64
    sys_call_table[__NR_fstat64] = org_sys_table[__NR_fstat64];
#endif
#ifdef __NR_lstat64
    sys_call_table[__NR_lstat64] = org_sys_table[__NR_lstat64];
#endif
#ifdef __NR_fstatat64
    sys_call_table[__NR_fstatat64] = org_sys_table[__NR_fstatat64];
#endif
#endif
#if BITS_PER_LONG == 32
#ifdef __NR_truncate64
    sys_call_table[__NR_truncate64] = org_sys_table[__NR_truncate64];
#endif
#ifdef __NR_ftruncate64
    sys_call_table[__NR_ftruncate64] = org_sys_table[__NR_ftruncate64];
#endif
#endif

#ifdef __NR_setxattr
    sys_call_table[__NR_setxattr] = org_sys_table[__NR_setxattr];
#endif
#ifdef __NR_lsetxattr
    sys_call_table[__NR_lsetxattr] = org_sys_table[__NR_lsetxattr];
#endif
#ifdef __NR_fsetxattr
    sys_call_table[__NR_fsetxattr] = org_sys_table[__NR_fsetxattr];
#endif
#ifdef __NR_getxattr
    sys_call_table[__NR_getxattr] = org_sys_table[__NR_getxattr];
#endif
#ifdef __NR_lgetxattr
    sys_call_table[__NR_lgetxattr] = org_sys_table[__NR_lgetxattr];
#endif
#ifdef __NR_fgetxattr
    sys_call_table[__NR_fgetxattr] = org_sys_table[__NR_fgetxattr];
#endif
#ifdef __NR_listxattr
    sys_call_table[__NR_listxattr] = org_sys_table[__NR_listxattr];
#endif
#ifdef __NR_llistxattr
    sys_call_table[__NR_llistxattr] = org_sys_table[__NR_llistxattr];
#endif
#ifdef __NR_flistxattr
    sys_call_table[__NR_flistxattr] = org_sys_table[__NR_flistxattr];
#endif
#ifdef __NR_removexattr
    sys_call_table[__NR_removexattr] = org_sys_table[__NR_removexattr];
#endif
#ifdef __NR_lremovexattr
    sys_call_table[__NR_lremovexattr] = org_sys_table[__NR_lremovexattr];
#endif
#ifdef __NR_fremovexattr
    sys_call_table[__NR_fremovexattr] = org_sys_table[__NR_fremovexattr];
#endif

#ifdef __NR_brk
    sys_call_table[__NR_brk] = org_sys_table[__NR_brk];
#endif
#ifdef __NR_mprotect
    sys_call_table[__NR_mprotect] = org_sys_table[__NR_mprotect];
#endif
#ifdef __NR_mremap
    sys_call_table[__NR_mremap] = org_sys_table[__NR_mremap];
#endif
#ifdef __NR_remap_file_pages
    sys_call_table[__NR_remap_file_pages] = org_sys_table[__NR_remap_file_pages];
#endif
#ifdef __NR_msync
    sys_call_table[__NR_msync] = org_sys_table[__NR_msync];
#endif
#ifdef __NR_fadvise64
    sys_call_table[__NR_fadvise64] = org_sys_table[__NR_fadvise64];
#endif
#ifdef __NR_fadvise64_64
    sys_call_table[__NR_fadvise64_64] = org_sys_table[__NR_fadvise64_64];
#endif
#ifdef __NR_munmap
    sys_call_table[__NR_munmap] = org_sys_table[__NR_munmap];
#endif
#ifdef __NR_mlock
    sys_call_table[__NR_mlock] = org_sys_table[__NR_mlock];
#endif
#ifdef __NR_munlock
    sys_call_table[__NR_munlock] = org_sys_table[__NR_munlock];
#endif
#ifdef __NR_mlockall
    sys_call_table[__NR_mlockall] = org_sys_table[__NR_mlockall];
#endif
#ifdef __NR_munlockall
    sys_call_table[__NR_munlockall] = org_sys_table[__NR_munlockall];
#endif
#ifdef __NR_madvise
    sys_call_table[__NR_madvise] = org_sys_table[__NR_madvise];
#endif
#ifdef __NR_mincore
    sys_call_table[__NR_mincore] = org_sys_table[__NR_mincore];
#endif

#ifdef __NR_pivot_root
    sys_call_table[__NR_pivot_root] = org_sys_table[__NR_pivot_root];
#endif
#ifdef __NR_chroot
    sys_call_table[__NR_chroot] = org_sys_table[__NR_chroot];
#endif
#ifdef __NR_mknod
    sys_call_table[__NR_mknod] = org_sys_table[__NR_mknod];
#endif
#ifdef __NR_link
    sys_call_table[__NR_link] = org_sys_table[__NR_link];
#endif
#ifdef __NR_symlink
    sys_call_table[__NR_symlink] = org_sys_table[__NR_symlink];
#endif
#ifdef __NR_unlink
    sys_call_table[__NR_unlink] = org_sys_table[__NR_unlink];
#endif
#ifdef __NR_rename
    sys_call_table[__NR_rename] = org_sys_table[__NR_rename];
#endif
#ifdef __NR_chmod
    sys_call_table[__NR_chmod] = org_sys_table[__NR_chmod];
#endif
#ifdef __NR_fchmod
    sys_call_table[__NR_fchmod] = org_sys_table[__NR_fchmod];
#endif

#ifdef __NR_fcntl
    sys_call_table[__NR_fcntl] = org_sys_table[__NR_fcntl];
#endif
#if BITS_PER_LONG == 32
#ifdef __NR_fcntl64
    sys_call_table[__NR_fcntl64] = org_sys_table[__NR_fcntl64];
#endif
#endif
#ifdef __NR_pipe
    sys_call_table[__NR_pipe] = org_sys_table[__NR_pipe];
#endif
#ifdef __NR_pipe2
    sys_call_table[__NR_pipe2] = org_sys_table[__NR_pipe2];
#endif
#ifdef __NR_dup
    sys_call_table[__NR_dup] = org_sys_table[__NR_dup];
#endif
#ifdef __NR_dup2
    sys_call_table[__NR_dup2] = org_sys_table[__NR_dup2];
#endif
#ifdef __NR_dup3
    sys_call_table[__NR_dup3] = org_sys_table[__NR_dup3];
#endif
#ifdef __NR_ioperm
    sys_call_table[__NR_ioperm] = org_sys_table[__NR_ioperm];
#endif
#ifdef __NR_ioctl
    sys_call_table[__NR_ioctl] = org_sys_table[__NR_ioctl];
#endif
#ifdef __NR_flock
    sys_call_table[__NR_flock] = org_sys_table[__NR_flock];
#endif
#ifdef __NR_io_setup
    sys_call_table[__NR_io_setup] = org_sys_table[__NR_io_setup];
#endif
#ifdef __NR_io_destroy
    sys_call_table[__NR_io_destroy] = org_sys_table[__NR_io_destroy];
#endif
#ifdef __NR_io_getevents
    sys_call_table[__NR_io_getevents] = org_sys_table[__NR_io_getevents];
#endif
#ifdef __NR_io_submit
    sys_call_table[__NR_io_submit] = org_sys_table[__NR_io_submit];
#endif
#ifdef __NR_io_cancel
    sys_call_table[__NR_io_cancel] = org_sys_table[__NR_io_cancel];
#endif
#ifdef __NR_sendfile
    sys_call_table[__NR_sendfile] = org_sys_table[__NR_sendfile];
#endif
#ifdef __NR_sendfile64
    sys_call_table[__NR_sendfile64] = org_sys_table[__NR_sendfile64];
#endif
#ifdef __NR_readlink
    sys_call_table[__NR_readlink] = org_sys_table[__NR_readlink];
#endif
#ifdef __NR_creat
    sys_call_table[__NR_creat] = org_sys_table[__NR_creat];
#endif
#ifdef __NR_open
    sys_call_table[__NR_open] = org_sys_table[__NR_open];
#endif
#ifdef __NR_close
    sys_call_table[__NR_close] = org_sys_table[__NR_close];
#endif
#ifdef __NR_access
    sys_call_table[__NR_access] = org_sys_table[__NR_access];
#endif
#ifdef __NR_vhangup
    sys_call_table[__NR_vhangup] = org_sys_table[__NR_vhangup];
#endif
#ifdef __NR_chown
    sys_call_table[__NR_chown] = org_sys_table[__NR_chown];
#endif
#ifdef __NR_lchown
    sys_call_table[__NR_lchown] = org_sys_table[__NR_lchown];
#endif
#ifdef __NR_fchown
    sys_call_table[__NR_fchown] = org_sys_table[__NR_fchown];
#endif
#ifdef CONFIG_HAVE_UID16
#ifdef __NR_chown16
    sys_call_table[__NR_chown16] = org_sys_table[__NR_chown16];
#endif
#ifdef __NR_lchown16
    sys_call_table[__NR_lchown16] = org_sys_table[__NR_lchown16];
#endif
#ifdef __NR_fchown16
    sys_call_table[__NR_fchown16] = org_sys_table[__NR_fchown16];
#endif
#ifdef __NR_setregid16
    sys_call_table[__NR_setregid16] = org_sys_table[__NR_setregid16];
#endif
#ifdef __NR_setgid16
    sys_call_table[__NR_setgid16] = org_sys_table[__NR_setgid16];
#endif
#ifdef __NR_setreuid16
    sys_call_table[__NR_setreuid16] = org_sys_table[__NR_setreuid16];
#endif
#ifdef __NR_setuid16
    sys_call_table[__NR_setuid16] = org_sys_table[__NR_setuid16];
#endif
#ifdef __NR_setresuid16
    sys_call_table[__NR_setresuid16] = org_sys_table[__NR_setresuid16];
#endif
#ifdef __NR_getresuid16
    sys_call_table[__NR_getresuid16] = org_sys_table[__NR_getresuid16];
#endif
#ifdef __NR_setresgid16
    sys_call_table[__NR_setresgid16] = org_sys_table[__NR_setresgid16];
#endif
#ifdef __NR_getresgid16
    sys_call_table[__NR_getresgid16] = org_sys_table[__NR_getresgid16];
#endif
#ifdef __NR_setfsuid16
    sys_call_table[__NR_setfsuid16] = org_sys_table[__NR_setfsuid16];
#endif
#ifdef __NR_setfsgid16
    sys_call_table[__NR_setfsgid16] = org_sys_table[__NR_setfsgid16];
#endif
#ifdef __NR_getgroups16
    sys_call_table[__NR_getgroups16] = org_sys_table[__NR_getgroups16];
#endif
#ifdef __NR_setgroups16
    sys_call_table[__NR_setgroups16] = org_sys_table[__NR_setgroups16];
#endif
#ifdef __NR_getuid16
    sys_call_table[__NR_getuid16] = org_sys_table[__NR_getuid16];
#endif
#ifdef __NR_geteuid16
    sys_call_table[__NR_geteuid16] = org_sys_table[__NR_geteuid16];
#endif
#ifdef __NR_getgid16
    sys_call_table[__NR_getgid16] = org_sys_table[__NR_getgid16];
#endif
#ifdef __NR_getegid16
    sys_call_table[__NR_getegid16] = org_sys_table[__NR_getegid16];
#endif
#endif

#ifdef __NR_utime
    sys_call_table[__NR_utime] = org_sys_table[__NR_utime];
#endif
#ifdef __NR_utimes
    sys_call_table[__NR_utimes] = org_sys_table[__NR_utimes];
#endif
#ifdef __NR_lseek
    sys_call_table[__NR_lseek] = org_sys_table[__NR_lseek];
#endif
#ifdef __NR_llseek
    sys_call_table[__NR_llseek] = org_sys_table[__NR_llseek];
#endif
#ifdef __NR_read
    sys_call_table[__NR_read] = org_sys_table[__NR_read];
#endif
#ifdef __NR_readahead
    sys_call_table[__NR_readahead] = org_sys_table[__NR_readahead];
#endif
#ifdef __NR_readv
    sys_call_table[__NR_readv] = org_sys_table[__NR_readv];
#endif
#ifdef __NR_write
    sys_call_table[__NR_write] = org_sys_table[__NR_write];
#endif
#ifdef __NR_writev
    sys_call_table[__NR_writev] = org_sys_table[__NR_writev];
#endif
#ifdef __NR_pread64
    sys_call_table[__NR_pread64] = org_sys_table[__NR_pread64];
#endif
#ifdef __NR_pwrite64
    sys_call_table[__NR_pwrite64] = org_sys_table[__NR_pwrite64];
#endif
#ifdef __NR_preadv
    sys_call_table[__NR_preadv] = org_sys_table[__NR_preadv];
#endif
#ifdef __NR_preadv2
    sys_call_table[__NR_preadv2] = org_sys_table[__NR_preadv2];
#endif
#ifdef __NR_pwritev
    sys_call_table[__NR_pwritev] = org_sys_table[__NR_pwritev];
#endif
#ifdef __NR_pwritev2
    sys_call_table[__NR_pwritev2] = org_sys_table[__NR_pwritev2];
#endif
#ifdef __NR_getcwd
    sys_call_table[__NR_getcwd] = org_sys_table[__NR_getcwd];
#endif
#ifdef __NR_mkdir
    sys_call_table[__NR_mkdir] = org_sys_table[__NR_mkdir];
#endif
#ifdef __NR_chdir
    sys_call_table[__NR_chdir] = org_sys_table[__NR_chdir];
#endif
#ifdef __NR_fchdir
    sys_call_table[__NR_fchdir] = org_sys_table[__NR_fchdir];
#endif
#ifdef __NR_rmdir
    sys_call_table[__NR_rmdir] = org_sys_table[__NR_rmdir];
#endif
#ifdef __NR_lookup_dcookie
    sys_call_table[__NR_lookup_dcookie] = org_sys_table[__NR_lookup_dcookie];
#endif
#ifdef __NR_quotactl
    sys_call_table[__NR_quotactl] = org_sys_table[__NR_quotactl];
#endif
#ifdef __NR_getdents
    sys_call_table[__NR_getdents] = org_sys_table[__NR_getdents];
#endif
#ifdef __NR_getdents64
    sys_call_table[__NR_getdents64] = org_sys_table[__NR_getdents64];
#endif

#ifdef __NR_setsockopt
    sys_call_table[__NR_setsockopt] = org_sys_table[__NR_setsockopt];
#endif
#ifdef __NR_getsockopt
    sys_call_table[__NR_getsockopt] = org_sys_table[__NR_getsockopt];
#endif
#ifdef __NR_bind
    sys_call_table[__NR_bind] = org_sys_table[__NR_bind];
#endif
#ifdef __NR_connect
    sys_call_table[__NR_connect] = org_sys_table[__NR_connect];
#endif
#ifdef __NR_accept
    sys_call_table[__NR_accept] = org_sys_table[__NR_accept];
#endif
#ifdef __NR_accept4
    sys_call_table[__NR_accept4] = org_sys_table[__NR_accept4];
#endif
#ifdef __NR_getsockname
    sys_call_table[__NR_getsockname] = org_sys_table[__NR_getsockname];
#endif
#ifdef __NR_getpeername
    sys_call_table[__NR_getpeername] = org_sys_table[__NR_getpeername];
#endif
#ifdef __NR_send
    sys_call_table[__NR_send] = org_sys_table[__NR_send];
#endif
#ifdef __NR_sendto
    sys_call_table[__NR_sendto] = org_sys_table[__NR_sendto];
#endif
#ifdef __NR_sendmsg
    sys_call_table[__NR_sendmsg] = org_sys_table[__NR_sendmsg];
#endif
#ifdef __NR_sendmmsg
    sys_call_table[__NR_sendmmsg] = org_sys_table[__NR_sendmmsg];
#endif
#ifdef __NR_recv
    sys_call_table[__NR_recv] = org_sys_table[__NR_recv];
#endif
#ifdef __NR_recvfrom
    sys_call_table[__NR_recvfrom] = org_sys_table[__NR_recvfrom];
#endif
#ifdef __NR_recvmsg
    sys_call_table[__NR_recvmsg] = org_sys_table[__NR_recvmsg];
#endif
#ifdef __NR_recvmmsg
    sys_call_table[__NR_recvmmsg] = org_sys_table[__NR_recvmmsg];
#endif
#ifdef __NR_socket
    sys_call_table[__NR_socket] = org_sys_table[__NR_socket];
#endif
#ifdef __NR_socketpair
    sys_call_table[__NR_socketpair] = org_sys_table[__NR_socketpair];
#endif
#ifdef __NR_socketcall
    sys_call_table[__NR_socketcall] = org_sys_table[__NR_socketcall];
#endif
#ifdef __NR_listen
    sys_call_table[__NR_listen] = org_sys_table[__NR_listen];
#endif
#ifdef __NR_poll
    sys_call_table[__NR_poll] = org_sys_table[__NR_poll];
#endif
#ifdef __NR_select
    sys_call_table[__NR_select] = org_sys_table[__NR_select];
#endif
#ifdef __NR_old_select
    sys_call_table[__NR_old_select] = org_sys_table[__NR_old_select];
#endif
#ifdef __NR_epoll_create
    sys_call_table[__NR_epoll_create] = org_sys_table[__NR_epoll_create];
#endif
#ifdef __NR_epoll_create1
    sys_call_table[__NR_epoll_create1] = org_sys_table[__NR_epoll_create1];
#endif
#ifdef __NR_epoll_ctl
    sys_call_table[__NR_epoll_ctl] = org_sys_table[__NR_epoll_ctl];
#endif
#ifdef __NR_epoll_wait
    sys_call_table[__NR_epoll_wait] = org_sys_table[__NR_epoll_wait];
#endif
#ifdef __NR_epoll_pwait
    sys_call_table[__NR_epoll_pwait] = org_sys_table[__NR_epoll_pwait];
#endif
#ifdef __NR_gethostname
    sys_call_table[__NR_gethostname] = org_sys_table[__NR_gethostname];
#endif
#ifdef __NR_sethostname
    sys_call_table[__NR_sethostname] = org_sys_table[__NR_sethostname];
#endif
#ifdef __NR_setdomainname
    sys_call_table[__NR_setdomainname] = org_sys_table[__NR_setdomainname];
#endif
#ifdef __NR_newuname
    sys_call_table[__NR_newuname] = org_sys_table[__NR_newuname];
#endif
#ifdef __NR_uname
    sys_call_table[__NR_uname] = org_sys_table[__NR_uname];
#endif
#ifdef __NR_olduname
    sys_call_table[__NR_olduname] = org_sys_table[__NR_olduname];
#endif

#ifdef __NR_getrlimit
    sys_call_table[__NR_getrlimit] = org_sys_table[__NR_getrlimit];
#endif
#ifdef __ARCH_WANT_SYS_OLD_GETRLIMIT
#ifdef __NR_old_getrlimit
    sys_call_table[__NR_old_getrlimit] = org_sys_table[__NR_old_getrlimit];
#endif
#endif
#ifdef __NR_setrlimit
    sys_call_table[__NR_setrlimit] = org_sys_table[__NR_setrlimit];
#endif
#ifdef __NR_prlimit64
    sys_call_table[__NR_prlimit64] = org_sys_table[__NR_prlimit64];
#endif
#ifdef __NR_getrusage
    sys_call_table[__NR_getrusage] = org_sys_table[__NR_getrusage];
#endif
#ifdef __NR_umask
    sys_call_table[__NR_umask] = org_sys_table[__NR_umask];
#endif

#ifdef __NR_msgget
    sys_call_table[__NR_msgget] = org_sys_table[__NR_msgget];
#endif
#ifdef __NR_msgsnd
    sys_call_table[__NR_msgsnd] = org_sys_table[__NR_msgsnd];
#endif
#ifdef __NR_msgrcv
    sys_call_table[__NR_msgrcv] = org_sys_table[__NR_msgrcv];
#endif
#ifdef __NR_msgctl
    sys_call_table[__NR_msgctl] = org_sys_table[__NR_msgctl];
#endif

#ifdef __NR_semget
    sys_call_table[__NR_semget] = org_sys_table[__NR_semget];
#endif
#ifdef __NR_semop
    sys_call_table[__NR_semop] = org_sys_table[__NR_semop];
#endif
#ifdef __NR_semctl
    sys_call_table[__NR_semctl] = org_sys_table[__NR_semctl];
#endif
#ifdef __NR_semtimedop
    sys_call_table[__NR_semtimedop] = org_sys_table[__NR_semtimedop];
#endif
#ifdef __NR_shmat
    sys_call_table[__NR_shmat] = org_sys_table[__NR_shmat];
#endif
#ifdef __NR_shmget
    sys_call_table[__NR_shmget] = org_sys_table[__NR_shmget];
#endif
#ifdef __NR_shmdt
    sys_call_table[__NR_shmdt] = org_sys_table[__NR_shmdt];
#endif
#ifdef __NR_shmctl
    sys_call_table[__NR_shmctl] = org_sys_table[__NR_shmctl];
#endif
#ifdef __NR_ipc
    sys_call_table[__NR_ipc] = org_sys_table[__NR_ipc];
#endif

#ifdef __NR_mq_open
    sys_call_table[__NR_mq_open] = org_sys_table[__NR_mq_open];
#endif
#ifdef __NR_mq_unlink
    sys_call_table[__NR_mq_unlink] = org_sys_table[__NR_mq_unlink];
#endif
#ifdef __NR_mq_timedsend
    sys_call_table[__NR_mq_timedsend] = org_sys_table[__NR_mq_timedsend];
#endif
#ifdef __NR_mq_timedreceive
    sys_call_table[__NR_mq_timedreceive] = org_sys_table[__NR_mq_timedreceive];
#endif
#ifdef __NR_mq_notify
    sys_call_table[__NR_mq_notify] = org_sys_table[__NR_mq_notify];
#endif
#ifdef __NR_mq_getsetattr
    sys_call_table[__NR_mq_getsetattr] = org_sys_table[__NR_mq_getsetattr];
#endif

#ifdef __NR_pciconfig_iobase
    sys_call_table[__NR_pciconfig_iobase] = org_sys_table[__NR_pciconfig_iobase];
#endif
#ifdef __NR_pciconfig_read
    sys_call_table[__NR_pciconfig_read] = org_sys_table[__NR_pciconfig_read];
#endif
#ifdef __NR_pciconfig_write
    sys_call_table[__NR_pciconfig_write] = org_sys_table[__NR_pciconfig_write];
#endif

#ifdef __NR_prctl
    sys_call_table[__NR_prctl] = org_sys_table[__NR_prctl];
#endif
#ifdef __NR_swapon
    sys_call_table[__NR_swapon] = org_sys_table[__NR_swapon];
#endif
#ifdef __NR_swapoff
    sys_call_table[__NR_swapoff] = org_sys_table[__NR_swapoff];
#endif
#ifdef __NR_sysctl
    sys_call_table[__NR_sysctl] = org_sys_table[__NR_sysctl];
#endif
#ifdef __NR_sysinfo
    sys_call_table[__NR_sysinfo] = org_sys_table[__NR_sysinfo];
#endif
#ifdef __NR_sysfs
    sys_call_table[__NR_sysfs] = org_sys_table[__NR_sysfs];
#endif
#ifdef __NR_syslog
    sys_call_table[__NR_syslog] = org_sys_table[__NR_syslog];
#endif
#ifdef __NR_uselib
    sys_call_table[__NR_uselib] = org_sys_table[__NR_uselib];
#endif
#ifdef __NR_ni_syscall
    sys_call_table[__NR_ni_syscall] = org_sys_table[__NR_ni_syscall];
#endif
#ifdef __NR_ptrace
    sys_call_table[__NR_ptrace] = org_sys_table[__NR_ptrace];
#endif

#ifdef __NR_add_key
    sys_call_table[__NR_add_key] = org_sys_table[__NR_add_key];
#endif

#ifdef __NR_request_key
    sys_call_table[__NR_request_key] = org_sys_table[__NR_request_key];
#endif

#ifdef __NR_keyctl
    sys_call_table[__NR_keyctl] = org_sys_table[__NR_keyctl];
#endif

#ifdef __NR_ioprio_set
    sys_call_table[__NR_ioprio_set] = org_sys_table[__NR_ioprio_set];
#endif
#ifdef __NR_ioprio_get
    sys_call_table[__NR_ioprio_get] = org_sys_table[__NR_ioprio_get];
#endif
#ifdef __NR_set_mempolicy
    sys_call_table[__NR_set_mempolicy] = org_sys_table[__NR_set_mempolicy];
#endif
#ifdef __NR_migrate_pages
    sys_call_table[__NR_migrate_pages] = org_sys_table[__NR_migrate_pages];
#endif
#ifdef __NR_move_pages
    sys_call_table[__NR_move_pages] = org_sys_table[__NR_move_pages];
#endif
#ifdef __NR_mbind
    sys_call_table[__NR_mbind] = org_sys_table[__NR_mbind];
#endif
#ifdef __NR_get_mempolicy
    sys_call_table[__NR_get_mempolicy] = org_sys_table[__NR_get_mempolicy];
#endif

#ifdef __NR_inotify_init
    sys_call_table[__NR_inotify_init] = org_sys_table[__NR_inotify_init];
#endif
#ifdef __NR_inotify_init1
    sys_call_table[__NR_inotify_init1] = org_sys_table[__NR_inotify_init1];
#endif
#ifdef __NR_inotify_add_watch
    sys_call_table[__NR_inotify_add_watch] = org_sys_table[__NR_inotify_add_watch];
#endif
#ifdef __NR_inotify_rm_watch
    sys_call_table[__NR_inotify_rm_watch] = org_sys_table[__NR_inotify_rm_watch];
#endif

#ifdef __NR_spu_run
    sys_call_table[__NR_spu_run] = org_sys_table[__NR_spu_run];
#endif
#ifdef __NR_spu_create
    sys_call_table[__NR_spu_create] = org_sys_table[__NR_spu_create];
#endif

#ifdef __NR_mknodat
    sys_call_table[__NR_mknodat] = org_sys_table[__NR_mknodat];
#endif
#ifdef __NR_mkdirat
    sys_call_table[__NR_mkdirat] = org_sys_table[__NR_mkdirat];
#endif
#ifdef __NR_unlinkat
    sys_call_table[__NR_unlinkat] = org_sys_table[__NR_unlinkat];
#endif
#ifdef __NR_symlinkat
    sys_call_table[__NR_symlinkat] = org_sys_table[__NR_symlinkat];
#endif
#ifdef __NR_linkat
    sys_call_table[__NR_linkat] = org_sys_table[__NR_linkat];
#endif
#ifdef __NR_renameat
    sys_call_table[__NR_renameat] = org_sys_table[__NR_renameat];
#endif
#ifdef __NR_renameat2
    sys_call_table[__NR_renameat2] = org_sys_table[__NR_renameat2];
#endif
#ifdef __NR_futimesat
    sys_call_table[__NR_futimesat] = org_sys_table[__NR_futimesat];
#endif
#ifdef __NR_faccessat
    sys_call_table[__NR_faccessat] = org_sys_table[__NR_faccessat];
#endif
#ifdef __NR_fchmodat
    sys_call_table[__NR_fchmodat] = org_sys_table[__NR_fchmodat];
#endif
#ifdef __NR_fchownat
    sys_call_table[__NR_fchownat] = org_sys_table[__NR_fchownat];
#endif
#ifdef __NR_openat
    sys_call_table[__NR_openat] = org_sys_table[__NR_openat];
#endif
#ifdef __NR_newfstatat
    sys_call_table[__NR_newfstatat] = org_sys_table[__NR_newfstatat];
#endif
#ifdef __NR_readlinkat
    sys_call_table[__NR_readlinkat] = org_sys_table[__NR_readlinkat];
#endif
#ifdef __NR_utimensat
    sys_call_table[__NR_utimensat] = org_sys_table[__NR_utimensat];
#endif
#ifdef __NR_unshare
    sys_call_table[__NR_unshare] = org_sys_table[__NR_unshare];
#endif

#ifdef __NR_splice
    sys_call_table[__NR_splice] = org_sys_table[__NR_splice];
#endif

#ifdef __NR_vmsplice
    sys_call_table[__NR_vmsplice] = org_sys_table[__NR_vmsplice];
#endif

#ifdef __NR_tee
    sys_call_table[__NR_tee] = org_sys_table[__NR_tee];
#endif

#ifdef __NR_sync_file_range
    sys_call_table[__NR_sync_file_range] = org_sys_table[__NR_sync_file_range];
#endif
#ifdef __NR_sync_file_range2
    sys_call_table[__NR_sync_file_range2] = org_sys_table[__NR_sync_file_range2];
#endif
#ifdef __NR_get_robust_list
    sys_call_table[__NR_get_robust_list] = org_sys_table[__NR_get_robust_list];
#endif
#ifdef __NR_set_robust_list
    sys_call_table[__NR_set_robust_list] = org_sys_table[__NR_set_robust_list];
#endif
#ifdef __NR_getcpu
    sys_call_table[__NR_getcpu] = org_sys_table[__NR_getcpu];
#endif
#ifdef __NR_signalfd
    sys_call_table[__NR_signalfd] = org_sys_table[__NR_signalfd];
#endif
#ifdef __NR_signalfd4
    sys_call_table[__NR_signalfd4] = org_sys_table[__NR_signalfd4];
#endif
#ifdef __NR_timerfd_create
    sys_call_table[__NR_timerfd_create] = org_sys_table[__NR_timerfd_create];
#endif
#ifdef __NR_timerfd_settime
    sys_call_table[__NR_timerfd_settime] = org_sys_table[__NR_timerfd_settime];
#endif
#ifdef __NR_timerfd_gettime
    sys_call_table[__NR_timerfd_gettime] = org_sys_table[__NR_timerfd_gettime];
#endif
#ifdef __NR_eventfd
    sys_call_table[__NR_eventfd] = org_sys_table[__NR_eventfd];
#endif
#ifdef __NR_eventfd2
    sys_call_table[__NR_eventfd2] = org_sys_table[__NR_eventfd2];
#endif
#ifdef __NR_memfd_create
    sys_call_table[__NR_memfd_create] = org_sys_table[__NR_memfd_create];
#endif
#ifdef __NR_userfaultfd
    sys_call_table[__NR_userfaultfd] = org_sys_table[__NR_userfaultfd];
#endif
#ifdef __NR_fallocate
    sys_call_table[__NR_fallocate] = org_sys_table[__NR_fallocate];
#endif
#ifdef __NR_old_readdir
    sys_call_table[__NR_old_readdir] = org_sys_table[__NR_old_readdir];
#endif
#ifdef __NR_pselect6
    sys_call_table[__NR_pselect6] = org_sys_table[__NR_pselect6];
#endif
#ifdef __NR_ppoll
    sys_call_table[__NR_ppoll] = org_sys_table[__NR_ppoll];
#endif
#ifdef __NR_fanotify_init
    sys_call_table[__NR_fanotify_init] = org_sys_table[__NR_fanotify_init];
#endif
#ifdef __NR_fanotify_mark
    sys_call_table[__NR_fanotify_mark] = org_sys_table[__NR_fanotify_mark];
#endif
#ifdef __NR_syncfs
    sys_call_table[__NR_syncfs] = org_sys_table[__NR_syncfs];
#endif

#ifdef __NR_fork
    sys_call_table[__NR_fork] = org_sys_table[__NR_fork];
#endif
#ifdef __NR_vfork
    sys_call_table[__NR_vfork] = org_sys_table[__NR_vfork];
#endif
#ifdef CONFIG_CLONE_BACKWARDS
#ifdef __NR_clone
    sys_call_table[__NR_clone] = org_sys_table[__NR_clone];
#endif
#else
#ifdef CONFIG_CLONE_BACKWARDS3
#ifdef __NR_clone
    sys_call_table[__NR_clone] = org_sys_table[__NR_clone];
#endif
#else
#ifdef __NR_clone
    sys_call_table[__NR_clone] = org_sys_table[__NR_clone];
#endif
#endif
#endif

#ifdef __NR_execve
    sys_call_table[__NR_execve] = org_sys_table[__NR_execve];
#endif

#ifdef __NR_perf_event_open
    sys_call_table[__NR_perf_event_open] = org_sys_table[__NR_perf_event_open];
#endif

#ifdef __NR_mmap_pgoff
    sys_call_table[__NR_mmap_pgoff] = org_sys_table[__NR_mmap_pgoff];
#endif
#ifdef __NR_old_mmap
    sys_call_table[__NR_old_mmap] = org_sys_table[__NR_old_mmap];
#endif
#ifdef __NR_name_to_handle_at
    sys_call_table[__NR_name_to_handle_at] = org_sys_table[__NR_name_to_handle_at];
#endif
#ifdef __NR_open_by_handle_at
    sys_call_table[__NR_open_by_handle_at] = org_sys_table[__NR_open_by_handle_at];
#endif
#ifdef __NR_setns
    sys_call_table[__NR_setns] = org_sys_table[__NR_setns];
#endif
#ifdef __NR_process_vm_readv
    sys_call_table[__NR_process_vm_readv] = org_sys_table[__NR_process_vm_readv];
#endif
#ifdef __NR_process_vm_writev
    sys_call_table[__NR_process_vm_writev] = org_sys_table[__NR_process_vm_writev];
#endif

#ifdef __NR_kcmp
    sys_call_table[__NR_kcmp] = org_sys_table[__NR_kcmp];
#endif
#ifdef __NR_finit_module
    sys_call_table[__NR_finit_module] = org_sys_table[__NR_finit_module];
#endif
#ifdef __NR_seccomp
    sys_call_table[__NR_seccomp] = org_sys_table[__NR_seccomp];
#endif
#ifdef __NR_getrandom
    sys_call_table[__NR_getrandom] = org_sys_table[__NR_getrandom];
#endif
#ifdef __NR_bpf
    sys_call_table[__NR_bpf] = org_sys_table[__NR_bpf];
#endif

#ifdef __NR_execveat
    sys_call_table[__NR_execveat] = org_sys_table[__NR_execveat];
#endif

#ifdef __NR_membarrier
    sys_call_table[__NR_membarrier] = org_sys_table[__NR_membarrier];
#endif
#ifdef __NR_copy_file_range
    sys_call_table[__NR_copy_file_range] = org_sys_table[__NR_copy_file_range];
#endif

#ifdef __NR_mlock2
    sys_call_table[__NR_mlock2] = org_sys_table[__NR_mlock2];
#endif

#ifdef __NR_pkey_mprotect
    sys_call_table[__NR_pkey_mprotect] = org_sys_table[__NR_pkey_mprotect];
#endif
#ifdef __NR_pkey_alloc
    sys_call_table[__NR_pkey_alloc] = org_sys_table[__NR_pkey_alloc];
#endif
#ifdef __NR_pkey_free
    sys_call_table[__NR_pkey_free] = org_sys_table[__NR_pkey_free];
#endif
#ifdef __NR_statx
    sys_call_table[__NR_statx] = org_sys_table[__NR_statx];
#endif

    // Re-enable write protection
    write_cr0(read_cr0() | 0x10000);
    
}

module_init(hello_init);
module_exit(hello_exit);

