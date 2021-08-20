obj-m += lkm_hello_world.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	sudo dmesg -C
	sudo insmod lkm_hello_world.ko
	sudo rmmod lkm_hello_world
	sudo dmesg
