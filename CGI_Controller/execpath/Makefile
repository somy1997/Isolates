modname = $(shell basename $(PWD))

#temp : 
#	echo $(modname)

all : $(modname).py
	python3 $(modname).py
	
init :
#	gedit $(modname).cpp &
	gedit * &	

backup :
	cp -r ~/Desktop/cgi_controller/* ~/Desktop/M.\ Tech\ Project/CGI\ Controller/
	
web :
	firefox http://localhost:8000/ &
	
	
