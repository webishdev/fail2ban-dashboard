package fail2ban_client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	ogórek "github.com/kisielk/og-rek"
	"github.com/nlpodyssey/gopickle/pickle"
	"github.com/nlpodyssey/gopickle/types"
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

type Fail2BanClient struct {
	socket  net.Conn
	encoder *ogórek.Encoder
}

func NewFail2BanClient(address string) (*Fail2BanClient, error) {
	socket, err := net.Dial("unix", address)
	if err != nil {
		return nil, err
	}

	encoder := ogórek.NewEncoder(socket)

	return &Fail2BanClient{
		socket,
		encoder,
	}, nil
}

func (f2bc *Fail2BanClient) GetVersion() (string, error) {
	result, err := f2bc.sendCommand([]string{versionCommand})
	if err != nil {
		return "", err
	}

	if versionTuple, tupleOk := result.(*types.Tuple); tupleOk {
		if versionStr, versionOk := versionTuple.Get(1).(string); versionOk {
			return versionStr, nil
		}
	}

	return "", errors.New("fetching version failed")
}

func (f2bc *Fail2BanClient) sendCommand(command []string) (interface{}, error) {
	err := f2bc.write(command)
	if err != nil {
		return nil, err
	}
	return f2bc.read()
}

func (f2bc *Fail2BanClient) write(command []string) error {
	err := f2bc.encoder.Encode(command)
	if err != nil {
		return err
	}
	_, err = f2bc.socket.Write([]byte(commandTerminator))
	if err != nil {
		return err
	}
	return nil
}

func (f2bc *Fail2BanClient) read() (interface{}, error) {
	reader := bufio.NewReader(f2bc.socket)

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
