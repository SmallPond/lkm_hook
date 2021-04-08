obj-m += db_hook.o 
CFLAGS_db_hook.o := -DLINUX_KERNEL_VERSION="`/bin/sh $(PWD)/kversion.sh`"

all: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 

install:
	sudo insmod ./db_hook.ko

remove:
	sudo rmmod db_hook


clean: 
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean