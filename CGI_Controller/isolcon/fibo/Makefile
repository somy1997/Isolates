modname = $(shell basename $(PWD))

all :
	CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-extldflags "-static"' .

clean : 
	rm $(modname)
	
init :
	gedit $(modname).go &
	
backup :
#	cp -r ~/Desktop/isolcon ~/Desktop/M.\ Tech\ Project/CGI\ Controller/
#	rm ~/Desktop/M.\ Tech\ Project/CGI\ Controller/isolcon/isolcon
	rsync -avr --exclude='~/Desktop/M.\ Tech\ Project/CGI\ Controller/$(modname)/$(modname)' ~/Desktop/$(modname) ~/Desktop/M.\ Tech\ Project/CGI\ Controller/
