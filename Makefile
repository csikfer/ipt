
all : iptcon.pm


iptcon.pm : iptcon.py
	yapp -v -m iptcon iptcon.py

install : iptcon.pm ipt ipt.sh
	./install.sh

uninstall :
	./install.sh remove
