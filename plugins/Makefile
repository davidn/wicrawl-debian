build_files = cowpatty-wpa-psk-bruteforce/cowpatty/cowpatty cowpatty-wpa-psk-bruteforce/cowpatty-fpga/cowpatty cowpatty-wpa-psk-bruteforce/cowpatty-fpga/picod/picod cowpatty-wpa-psk-bruteforce/cowpatty-fpga/picod/picoc cowpatty-wpa-psk-bruteforce/cowpatty-fpga/picod/listflash pickupline/pul/pul

all: $(build_files)

$(build_files):
	cd `dirname $@` && $(MAKE) `basename $@`

clean:
	cd cowpatty-wpa-psk-bruteforce/cowpatty && $(MAKE) clean
	cd cowpatty-wpa-psk-bruteforce/cowpatty-fpga/picod && $(MAKE) clean
	cd cowpatty-wpa-psk-bruteforce/cowpatty-fpga && $(MAKE) clean
	cd pickupline/pul && $(MAKE) clean
