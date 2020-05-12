# Isolates

All the work is manually being logged in Isolates/Weeks.txt

## Searching System Call Table

Tried various methods to get pointers to system calls in linux kernel as a first step in isolating calls made by processes in order to create language agnostic isolates.

Commit URL : https://github.com/somy1997/Isolates/tree/b11fe4b73011aab0e7143dcc7954f8e3e63d7ce5

Methods Tried :
    
1. **Searching the table in the memory using a while loop** :\
Source Files : Isolates/System call intercept via LKM/intercept_open/
    
1. **Finding System call table's address using System.map** :\
Source Files : Isolates/System call intercept via LKM/intercept_unlink/
    
1. **Using function kallsyms_lookup_name** :\
Source Files : Isolates/System call intercept via LKM/intercept_sof/

We will be using this Method 3 hereon as its most convenient and takes least amount of time.  

## Logging System Calls using LKM

Logging calls made to system calls in linux kernel using LKM by creating custom function wrapper over it and for each syscall, logging to kernel details like syscall name, process name, process id and user id.

1. **Open System Call** :\
Commit URL : https://github.com/somy1997/Isolates/tree/b699d702659335e1326287281ea0c010364555a5\
\
Source Files                    : Isolates/System Call Logging\
Custom Open Function LKM Source : Isolates/System Call Logging/open/intercept_open.c\
Kernel logs                     : Isolates/System Call Logging/dmesglogs.txt

1. **File operations like open, close, read, write** :\
Commit URL : https://github.com/somy1997/Isolates/tree/49e1e954462e1a02aa2ba477ade0bc3d104d96a9