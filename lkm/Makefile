obj-m += bloom_lkm.o
obj-m += bloom_build_profile.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

bloom_build_profile.ko: bloom_build_profile.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean