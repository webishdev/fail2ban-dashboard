package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/kisielk/og-rek"
	"github.com/nlpodyssey/gopickle/pickle"
	"github.com/nlpodyssey/gopickle/types"
	"net"
)

const (
	commandTerminator    = "<F2B_END_COMMAND>"
	pingCommand          = "ping"
	statusCommand        = "status"
	versionCommand       = "version"
	banTimeCommandFmt    = "get %s bantime"
	findTimeCommandFmt   = "get %s findtime"
	maxRetriesCommandFmt = "get %s maxretry"
	socketReadBufferSize = 1024
)

type Py_builtins_str struct{}

func (c Py_builtins_str) Call(args ...interface{}) (interface{}, error) {
	return args[0], nil
}

func sendCommand(socket net.Conn, encoder *ogórek.Encoder, command []string) (interface{}, error) {
	err := write(socket, encoder, command)
	if err != nil {
		return nil, err
	}
	return read(socket)
}

func write(socket net.Conn, encoder *ogórek.Encoder, command []string) error {
	err := encoder.Encode(command)
	if err != nil {
		return err
	}
	_, err = socket.Write([]byte(commandTerminator))
	if err != nil {
		return err
	}
	return nil
}

func read(socket net.Conn) (interface{}, error) {
	reader := bufio.NewReader(socket)

	data := []byte{}
	for {
		buf := make([]byte, socketReadBufferSize)
		_, err := reader.Read(buf)
		if err != nil {
			return nil, err
		}
		data = append(data, buf...)
		containsTerminator := bytes.Contains(data, []byte(commandTerminator))
		if containsTerminator {
			break
		}
	}

	bufReader := bytes.NewReader(data)
	unpickler := pickle.NewUnpickler(bufReader)

	unpickler.FindClass = func(module, name string) (interface{}, error) {
		if (module == "builtins" || module == "__builtin__") && name == "str" {
			return &Py_builtins_str{}, nil
		}
		return nil, fmt.Errorf("class not found: [%s] %s", module, name)
	}

	return unpickler.Load()
}

func main() {
	fmt.Println("This is fail2ban-dashboard v1")

	p, err := pickle.Loads("U\x05Caf\xc3\xa9q\x00.")

	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", p)

	socketPath := "/var/run/fail2ban/fail2ban.sock"
	currentSocket, err := net.Dial("unix", socketPath)

	if err != nil {
		panic(err)
	}

	encoder := ogórek.NewEncoder(currentSocket)

	result, err := sendCommand(currentSocket, encoder, []string{versionCommand})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", result)

	result, err = sendCommand(currentSocket, encoder, []string{pingCommand, "100"})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", result)

	result, err = sendCommand(currentSocket, encoder, []string{statusCommand})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", result)

	if lvl1, ok := result.(*types.Tuple); ok {
		fmt.Printf("%#v\n", lvl1.String())
	}

	result, err = sendCommand(currentSocket, encoder, []string{statusCommand, "--all"})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%#v\n", result)

	if lvl1, ok := result.(*types.Tuple); ok {
		fmt.Printf("%#v\n", lvl1.String())
	}
}
