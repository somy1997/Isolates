obj-m += intercept_open.o

all : intercept_open.c
	# make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$(PWD) modules

clean : 
	#make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	make -C /usr/src/linux-headers-$(shell uname -r) SUBDIRS=$(PWD) clean
