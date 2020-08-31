package main

import (
	"crypto/rand"
	"fmt"
)

func main() {
	a := make([]byte, 5)
	fmt.Println(a)
	a = a[:3]
	fmt.Println(a)
	fmt.Println(a[:])
	b, _ := rand.Read(a[:])
	fmt.Println(b)
	fmt.Println(a[:])

}
