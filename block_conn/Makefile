obj-m += lkm_block_conn.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	sudo dmesg -C
test:
	sudo dmesg -C
	sudo python3 -m http.server 80 --bind 127.0.0.1 &
	curl http://localhost:80/
	sudo insmod lkm_block_conn.ko
	curl http://localhost:80/
	sudo rmmod lkm_block_conn
	kill %1
	sudo dmesg
