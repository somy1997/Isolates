# Isolates

All the work is manually being logged in Isolates/Weeks.txt

## System Call Intercepting

Trying various methods to intercept system calls in linux kernel as a first step in isolating calls made by processes in order to create language agnostic isolates.

Commit URL : https://github.com/somy1997/Isolates/tree/b11fe4b73011aab0e7143dcc7954f8e3e63d7ce5

Source Files : Isolates/System call intercept via LKM/

Methods Tested :

1. Intercepting system call by searching for system call table and then replacing Open system call's handle in the system call table : http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-7-SECT-2.html
    
    1. Searching system call table in the memory using a while loop : Isolates/System call intercept via LKM/intercept_open/
    
    1. Finding System call table's address using System.map         : Isolates/System call intercept via LKM/intercept_unlink/

1. Intercepting system call by replacing system call's handle in the system call table by modifying the write bit in the memory : https://stackoverflow.com/questions/59812156/how-can-i-override-a-system-call-table-entry-with-my-own-function
    
    1. System call table's address is directly available from the function kallsyms_lookup_name : Isolates/System call intercept via LKM/intercept_sof/

## System Call Logging using LKM

Logging calls made to open system call in linux kernel using LKM by creating custom open function wrapper over it and for each open syscall, logging to kernel details like syscall name, process name, process id and user id.

Commit URL : https://github.com/somy1997/Isolates/tree/b699d702659335e1326287281ea0c010364555a5

Source Files                    : Isolates/System Call Logging\
Custom Open Function LKM Source : Isolates/System Call Logging/open/intercept_open.c\
Kernel logs                     : Isolates/System Call Logging/dmesglogs.txt\