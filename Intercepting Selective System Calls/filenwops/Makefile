modname = $(shell basename $(PWD))

obj-m += $(modname).o

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
