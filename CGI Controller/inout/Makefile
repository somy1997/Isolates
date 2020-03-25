modname = $(shell basename $(PWD))

obj-m += $(modname).o

EXTRA_CFLAGS := -Wno-unused-function

#temp : 
#	echo $(modname)

all : $(modname).cpp
	sudo g++ -o /usr/lib/cgi-bin/$(modname) $(modname).cpp

clean : 
	sudo rm /usr/lib/cgi-bin/$(modname)
	
init :
#	gedit $(modname).cpp &
	gedit *.cpp &	
backup :
	cp -r ~/Desktop/cgi_controller/* ~/Desktop/M.\ Tech\ Project/CGI\ Controller/
	
web :
	firefox http://localhost/cgi-bin/$(modname)?11111 &
	
test : test.cpp
	g++ -o test test.cpp
	
