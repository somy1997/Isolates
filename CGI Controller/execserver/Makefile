modname = $(shell basename $(PWD))

#temp : 
#	echo $(modname)

all : $(modname).go
	go build $(modname).go
	
clean :
	rm $(modname)

run :
	./$(modname)

# backup :
# 	cp -r ~/Desktop/cgi_controller/* ~/Desktop/M.\ Tech\ Project/CGI\ Controller/
	
web :
	firefox http://localhost:8080/ &
	
	
