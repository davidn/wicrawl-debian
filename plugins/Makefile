include ../config.mk

all: clean wicrawl

AIRCRACK_MK=Makefile
ifeq ($(OS), Darwin)
	AIRCRACK_MK=Makefile.osx
endif

wicrawl: 
	@cd aircrack-wep-cracking/aircrack-ng-0.9.1 && $(MAKE) -f $(AIRCRACK_MK)
	@cd cowpatty-wpa-psk-bruteforce/cowpatty && $(MAKE)
	@cd cowpatty-wpa-psk-bruteforce/cowpatty-fpga/picod && $(MAKE)
	@cd cowpatty-wpa-psk-bruteforce/cowpatty-fpga && $(MAKE)
	@cd weplab-bruteforce/weplab-0.1.5 && ./configure && $(MAKE)
	@cd pickupline/pul && $(MAKE)

clean:
	@cd aircrack-wep-cracking/aircrack-ng-0.9.1 && $(MAKE) clean
	@cd cowpatty-wpa-psk-bruteforce/cowpatty && $(MAKE) clean
	@cd cowpatty-wpa-psk-bruteforce/cowpatty-fpga/picod && $(MAKE) clean
	@cd cowpatty-wpa-psk-bruteforce/cowpatty-fpga && $(MAKE) clean
	@cd pickupline/pul && $(MAKE) clean
