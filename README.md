# Isolates

All the work is manually being logged in Isolates/Weeks.txt

## Searching System Call Table

Tried various methods to get pointers to system calls in linux kernel as a first step in isolating calls made by processes in order to create language agnostic isolates.

Commit URL : https://github.com/somy1997/Isolates/tree/b11fe4b73011aab0e7143dcc7954f8e3e63d7ce5

Methods Tried :
    
1. **Searching the table in the memory using a while loop :**\
Source Files : Isolates/System call intercept via LKM/intercept_open/
    
1. **Finding System call table's address using System.map :**\
Source Files : Isolates/System call intercept via LKM/intercept_unlink/
    
1. **Using function kallsyms_lookup_name :**\
Source Files : Isolates/System call intercept via LKM/intercept_sof/

We will be using this Method 3 hereon as its most convenient and takes least amount of time.  

## Logging System Calls using LKM

Logging calls made to system calls in linux kernel using LKM by creating custom function wrapper over it and for each syscall, logging to kernel details like syscall name, process name, process id and user id.

1. **Open System Call :**\
Commit URL : https://github.com/somy1997/Isolates/tree/b699d702659335e1326287281ea0c010364555a5 \
Source Files                    : Isolates/System Call Logging/open/\
Custom Open Function LKM Source : Isolates/System Call Logging/open/intercept_open.c\
Kernel logs                     : Isolates/System Call Logging/dmesglogs.txt

1. **File operations like open, close, read, write :**\
Commit URL : https://github.com/somy1997/Isolates/tree/bd39c78b854009e76b89228a3e05ba43fbd2bc3f \
Source Files                    : Isolates/Logging System Calls/fileops/\
Kernel logs                     : Isolates/Logging System Calls/fileops/dmesglogs.txt

## Intercepting Selective System Calls 

Intercepting selective System Calls in linux kernel based on parent PIDs of the processes.

1. **File operations like open, close, read, write :**\
Commit URL : https://github.com/somy1997/Isolates/tree/744d29e418d38fd5c5f3d2878647a44bf3273c49 \
Source Files                    : Isolates/Intercepting Selective System Calls/fileops/\
Kernel logs                     : Isolates/Intercepting Selective System Calls/fileops/dmesglogs.txt

1. **File and network operations :**\
Commit URL : https://github.com/somy1997/Isolates/tree/744d29e418d38fd5c5f3d2878647a44bf3273c49 \
Source Files                    : Isolates/Intercepting Selective System Calls/filenwops/\
Kernel logs                     : Isolates/Intercepting Selective System Calls/filenwops/dmesglogs.txt

1. **All syscalls :**\
Commit URL : https://github.com/somy1997/Isolates/tree/744d29e418d38fd5c5f3d2878647a44bf3273c49 \
Source Files                    : Isolates/Intercepting Selective System Calls/reallops/\
Kernel logs                     : Isolates/Intercepting Selective System Calls/reallops/dmesglogs.txt\
Map from syscalls to flags      : Isolates/Intercepting Selective System Calls/reallops/syscalltoflag.csv\
Syscalls List                   : Isolates/Intercepting Selective System Calls/reallops/syscallslist.c

1. **Interactive Kernel (allows PPID to change) :**\
Commit URL : https://github.com/somy1997/Isolates/tree/744d29e418d38fd5c5f3d2878647a44bf3273c49 \
Source Files                    : Isolates/Intercepting Selective System Calls/iallops/\
Kernel logs                     : Isolates/Intercepting Selective System Calls/iallops/dmesglogs.txt

## CGI Controller

Created a simple CGI Controller in Go which executes the file given by the path in the URL. Its PID is used as PPID in the above kernels for intercepting purposes.

Commit URL : https://github.com/somy1997/Isolates/tree/744d29e418d38fd5c5f3d2878647a44bf3273c49 \
Source Files                    : Isolates/CGI Controller/isolcon/

## Stats and Plots

Compared our system with conventional container based open source platform Open Lambda.

Commit URL : https://github.com/somy1997/Isolates/tree/c470df3ab6a5c7429f99f930ed3080bae68c53e6
Source Files                    : Isolates/Intercepting_Selective_System_Calls/stats/