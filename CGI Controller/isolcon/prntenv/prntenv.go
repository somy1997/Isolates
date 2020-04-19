package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	// Set custom env variable
	// os.Setenv("CUSTOM", "500")

	// fetcha all env variables
	fmt.Println("content-type: text/html")
	fmt.Println("<h1>CGI Environment Variables</h1>")
	fmt.Println("<p>", os.Environ(), "</p")
	for _, element := range os.Environ() {
		variable := strings.Split(element, "=")
		fmt.Println("<p>", variable[0], "=>", variable[1], "</p>")
	}

	// fetch specific env variables
	// fmt.Println("CUSTOM=>", os.Getenv("CUSTOM"))
	// fmt.Println("GOROOT=>", os.Getenv("GOROOT"))
}
