package main

import (
	"net/http"
	"os/exec"

	"./cgiserver"
)

func main() {
	c := cgiserver.CgiServer()
	c.DefaultApp = "test/run.sh"
	c.LangMap[".sh"], _ = exec.LookPath("bash")
	c.LangMap[".php"], _ = exec.LookPath("php-cgi")
	http.ListenAndServe(":8080", c)
}
