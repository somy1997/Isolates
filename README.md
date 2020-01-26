# Isolates

All the work is manually being logged in Isolates /Weeks.txt

## Intercepting System Calls using LKM

Commit URL : https://github.com/somy1997/Isolates/tree/b11fe4b73011aab0e7143dcc7954f8e3e63d7ce5

Source Files : Isolates/System call intercept via LKM/

Methods Tested :

1. Intercepting system call by searching for system call table and then replacing Open system call's handle in the system call table : http://books.gigatux.nl/mirror/networksecuritytools/0596007949/networkst-CHP-7-SECT-2.html
    
        a. Searching system call table in the memory using a while loop : Isolates/System call intercept via LKM/intercept_open/
    
        b. Finding System call table's address using System.map         : Isolates/System call intercept via LKM/intercept_unlink/

2. Intercepting system call by replacing system call's handle in the system call table by modifying the write bit in the memory : https://stackoverflow.com/questions/59812156/how-can-i-override-a-system-call-table-entry-with-my-own-function
    
        a. System call table's address is directly available from the function kallsyms_lookup_name : Isolates/System call intercept via LKM/intercept_sof/