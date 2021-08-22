obj-m += lkm_hide_file.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo dmesg -C
	sudo insmod lkm_hide_file.ko
	ls /home/ubuntu/Desktop/
	sudo rmmod lkm_hide_file
	sudo dmesg
