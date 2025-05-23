package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/kisielk/og-rek"
	"github.com/nlpodyssey/gopickle/pickle"
	fail2ban_client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"net"
)

const (
	commandTerminator    = "<F2B_END_COMMAND>"
	pingCommand          = "ping"
	statusCommand        = "status"
	versionCommand       = "version"
	bannedCommand        = "banned"
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

	socketPath := "/var/run/fail2ban/fail2ban.sock"

	client, err := fail2ban_client.NewFail2BanClient(socketPath)

	if err != nil {
		panic(err)
	}

	version, err := client.GetVersion()

	if err != nil {
		panic(err)
	}

	fmt.Printf("fail2ban version found: %s\n", version)

	names, err := client.GetJailNames()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Jail names: %v\n", names)

	for _, jailName := range names {
		jailEntry, getErr := client.GetBanned(jailName)
		if getErr != nil {
			panic(getErr)
		}

		fmt.Printf("Banned IPs: %v\n", jailEntry)
	}
}
