package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
)

func fibo(n int) int {
	a, b, c := 0, 1, 0
	b = 1
	c = 0
	for i := 1; i < n; i++ {
		c = a + b
		a = b
		b = c
	}
	return a
}

func main() {
	fmt.Print("content-type: text/html\r\n\r\n")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()

	if scanner.Err() != nil {
		// handle error.
		fmt.Println("Error here.")
	} else {
		n, _ := strconv.Atoi(scanner.Text())
		fmt.Println(fibo(n))
	}
}
