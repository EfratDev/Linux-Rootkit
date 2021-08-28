obj-m += lkm_block_conn.o
USEMODULE += posix

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo dmesg -C
test:
	sudo dmesg -C
	sudo python3 -m http.server 80 --bind 0.0.0.0
	sudo insmod lkm_block_conn.ko
	# CURL FROM X.X.X.X
