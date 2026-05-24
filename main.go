package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

const (
	socksVersion = 0x05

	methodNoAuth        = 0x00
	methodUserPass      = 0x02
	methodNotAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03

	repSuccess             = 0x00
	repGeneralFailure      = 0x01
	repCommandNotSupported = 0x07
	repAddressNotSupported = 0x08
)

func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(client net.Conn) {
	defer client.Close()

	method, err := negotiateAuth(client)
	if err != nil {
		return
	}

	if method == methodUserPass {
		if err := authenticateUserPass(client); err != nil {
			return
		}
	}

	targetAddr, err := readConnectRequest(client)
	if err != nil {
		sendReply(client, repGeneralFailure)
		return
	}

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		sendReply(client, repGeneralFailure)
		return
	}
	defer target.Close()

	if err := sendReply(client, repSuccess); err != nil {
		return
	}

	relay(client, target)
}
func negotiateAuth(conn net.Conn) (byte, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, err
	}

	if header[0] != socksVersion {
		return 0, fmt.Errorf("unsupported SOCKS version")
	}

	nMethods := int(header[1])
	methods := make([]byte, nMethods)

	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, err
	}

	requiredMethod := byte(methodNoAuth)
	if os.Getenv("PROXY_USER") != "" {
		requiredMethod = methodUserPass
	}

	for _, method := range methods {
		if method == requiredMethod {
			conn.Write([]byte{socksVersion, requiredMethod})
			return requiredMethod, nil
		}
	}

	conn.Write([]byte{socksVersion, methodNotAcceptable})
	return 0, fmt.Errorf("no acceptable auth method")
}

func authenticateUserPass(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	if header[0] != 0x01 {
		conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid auth version")
	}

	uLen := int(header[1])
	username := make([]byte, uLen)

	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return err
	}

	pLen := int(pLenBuf[0])
	password := make([]byte, pLen)

	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	expectedUser := os.Getenv("PROXY_USER")
	expectedPass := os.Getenv("PROXY_PASS")

	if string(username) == expectedUser && string(password) == expectedPass {
		conn.Write([]byte{0x01, 0x00})
		return nil
	}

	conn.Write([]byte{0x01, 0x01})
	return fmt.Errorf("invalid credentials")
}

func readConnectRequest(conn net.Conn) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}

	if header[0] != socksVersion {
		return "", fmt.Errorf("invalid SOCKS version")
	}

	if header[1] != cmdConnect {
		sendReply(conn, repCommandNotSupported)
		return "", fmt.Errorf("unsupported command")
	}

	atyp := header[3]

	var host string

	switch atyp {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", err
		}
		host = net.IP(addr).String()

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", err
		}

		domainLen := int(lenBuf[0])
		domain := make([]byte, domainLen)

		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", err
		}

		host = string(domain)

	default:
		sendReply(conn, repAddressNotSupported)
		return "", fmt.Errorf("unsupported address type")
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", err
	}

	port := binary.BigEndian.Uint16(portBuf)

	return fmt.Sprintf("%s:%d", host, port), nil
}

func sendReply(conn net.Conn, rep byte) error {
	reply := []byte{
		socksVersion,
		rep,
		0x00,
		atypIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	_, err := conn.Write(reply)
	return err
}

func relay(client net.Conn, target net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(target, client)

		if tcpConn, ok := target.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(client, target)

		if tcpConn, ok := client.(*net.TCPConn); ok {
			tcpConn.CloseWrite()
		}
	}()

	wg.Wait()
}