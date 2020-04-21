modname = $(shell basename $(PWD))

obj-m += $(modname).o

EXTRA_CFLAGS := -Wno-unused-function

#temp : 
#	echo $(modname)

all : $(modname).c
	# make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$(PWD) modules

clean : 
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$(PWD) clean

insmod : $(modname).ko
	sudo insmod $(modname).ko

rmmod :
	sudo rmmod $(modname)
	
init :
#	cp backedreallops.c reallops.c
	gedit $(modname).c &
	
backup :
	cp -r ~/Desktop/intercept_log/* ~/Desktop/M.\ Tech\ Project/System\ Call\ Selective\ Blocking/
	
clins :
	make clean all insmod

dmesg :
	dmesg | grep ISOL > dmesglogs.txt
	
dmtail :
	dmesg | tail
