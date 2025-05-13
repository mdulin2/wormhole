package main

import (
	"fmt"

	"example.com/greetings"
)

func main() {
	fmt.Println("hello world")
	fmt.Println(greetings.Hello("Alex"))
}
