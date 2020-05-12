modname = $(shell basename $(PWD))

EXTRA_CFLAGS := -Wno-unused-function -I$(src)
obj-m := kiallops.o
kiallops-y := iallops.o custmap.o


#temp : 
#	echo iallops

all :
	# make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$(PWD) KBUILD_EXTMOD=$(PWD) modules

custmap.o :
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$(PWD) custmap.o

iallops.o :
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$(PWD) KBUILD_EXTMOD=$(PWD) iallops.o

clean : 
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$(PWD) clean

insmod : kiallops.ko
	sudo insmod kiallops.ko

rmmod :
	sudo rmmod kiallops
	
init :
#	cp backedreallops.c reallops.c
	gedit iallops.c &
	
backup :
	cp -r ~/Desktop/intercept_log/iallops ~/Desktop/M.\ Tech\ Project/System\ Call\ Selective\ Blocking/
	
clins :
	make clean all insmod

dmesg :
	dmesg | grep ISOL > dmesglogs.txt
	
dmtail :
	dmesg | tail
