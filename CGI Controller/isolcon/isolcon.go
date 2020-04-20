package main

import (
	"log"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
)

func pagewriter(w http.ResponseWriter, r *http.Request) {
	//fmt.Fprintln(w, r.URL, r.URL.Scheme, r.URL.Opaque, r.URL.User, r.URL.Host, r.URL.Path, r.URL.RawPath, r.URL.ForceQuery, r.URL.RawQuery, r.URL.Fragment)
	// fmt.Fprintln(w, r.URL.Path)

	path := r.URL.Path
	path = filepath.FromSlash(path)
	root, _ := filepath.Abs(".")
	path = filepath.Join(root, path)
	// path = filepath.Clean(path)

	finf, err := os.Stat(path)
	if err != nil {
		http.Error(w, "File Not Found", 404)
		return
	}

	fmod := finf.Mode()

	if !fmod.IsRegular() {
		http.Error(w, "Requires regular file", 403)
		return
	}

	if fmod.Perm()&0100 == 0 {
		http.Error(w, "Requires executable file", 403)
		return
	}

	if iscgi {
		cgih.Path = path
		cgih.Dir = root
		cgih.ServeHTTP(w, r)

	} else {
		cmd := exec.Command(path)
		cmd.Stdout = w
		err = cmd.Run()
		if err != nil {
			log.Fatal(err)
		}
	}

}

var iscgi bool
var cgih cgi.Handler

func main() {
	iscgi = true
	http.HandleFunc("/", pagewriter)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
