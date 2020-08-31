package main

import (
	"flag"
	"fmt"
	"net"
)

var lagServer = flag.Bool("s", false, "server")
var flagClient = flag.Bool("c", false, "client")

func handleConn(client net.Conn) {
	defer client.Close()
	for {

	}
}

func server(ip string, port string) bool {
	s, err := net.Listen("tcp", port)
	if err != nil {
		fmt.Println("listen error")
		return false
	}

	for {
		client, err := s.Accept()
		if err != nil {

		}

		go handleConn(client)
	}
}

func handleRequest(conn net.Conn) {
	defer conn.Close()

}

func client(ip string, port string) {
	conn, err := net.Dial(ip, port)
	if err != nil {
		fmt.Println("connect error")
		return
	}

	go handleRequest(conn)
}

func main() {
	flag.Parse()
}
