package main

import (
	"log"
	"net/http"
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

	// fmt.Fprintln(w, r.URL.Path, path)
	// var b bytes.Buffer
	cmd := exec.Command(path)
	// cmd.Stdout = &b
	cmd.Stdout = w
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}

	// fmt.Fprintln(w, "yo")
	// fmt.Fprintln(w, "wassup\nyo yo")
	// fmt.Fprintln(w, io.EOF)
	// fmt.Fprintln(w, b.String())
	// fmt.Println(b)
	// var s string = b.String()
	// s = strings.TrimSuffix(s)
	// fmt.Print(s)
	//io.WriteString(w, s[:len(s)-1])
	// s = "yo wassup"
	// fmt.Fprint(w, b.String())
	// fmt.Print(w, b.String())
}

func main() {
	http.HandleFunc("/", pagewriter)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
