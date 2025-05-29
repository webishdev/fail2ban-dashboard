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
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	commandTerminator    = "<F2B_END_COMMAND>"
	pingCommand          = "ping"
	statusCommand        = "status"
	versionCommand       = "version"
	getCommand           = "get"
	bannedCommand        = "banned"
	socketReadBufferSize = 1024
)

const (
	protocolNumberOfJail string = "Number of jail"
	protocolJailList     string = "Jail list"
)

type BanEntry struct {
	Address       string
	BannedAt      time.Time
	CurrenPenalty string
	BanEndsAt     time.Time
	JailName      string
	CountryCode   string
}

type JailEntry struct {
	Name          string
	BannedEntries []*BanEntry
}

type JailInfo struct {
	CurrentlyFailed int
	TotalFailed     int
	CurrentlyBanned int
	TotalBanned     int
}

type Fail2BanClient struct {
	mutex   sync.RWMutex
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
		socket:  socket,
		encoder: encoder,
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

func (f2bc *Fail2BanClient) GetJailNames() ([]string, error) {
	result, err := f2bc.sendCommand([]string{statusCommand})
	if err != nil {
		return []string{}, err
	}

	expectedJailCount := 0

	if statusTuple, tupleOk := result.(*types.Tuple); tupleOk {
		if statusList, listOk := statusTuple.Get(1).(*types.List); listOk {
			if numberOfJailsTuple, numberTupleOk := statusList.Get(0).(*types.Tuple); numberTupleOk {
				if numberOfJailsKey, numberOfJailsKeyOk := numberOfJailsTuple.Get(0).(string); numberOfJailsKeyOk {
					if numberOfJailsKey == protocolNumberOfJail {
						if numberOfJails, numberOfJailsOk := numberOfJailsTuple.Get(1).(int); numberOfJailsOk {
							expectedJailCount = numberOfJails
						} else {
							return []string{}, errors.New("number of jails could not be read")
						}
					}
				}
			}
			if jailListTuple, jailListTupleOk := statusList.Get(1).(*types.Tuple); jailListTupleOk {
				if jailListKey, jailListKeyOk := jailListTuple.Get(0).(string); jailListKeyOk {
					if jailListKey == protocolJailList {
						if jailList, jailListOk := jailListTuple.Get(1).(string); jailListOk {
							jailNames := strings.Split(jailList, ",")

							for i := range jailNames {
								jailNames[i] = strings.TrimSpace(jailNames[i])
							}

							if len(jailNames) != expectedJailCount {
								return []string{}, errors.New("number of jails did not match")
							}
							return jailNames, nil
						} else {
							return []string{}, errors.New("jail list could not be read")
						}
					}
				}
			}
		}
	}

	return []string{}, errors.New("fetching status failed")
}

func (f2bc *Fail2BanClient) GetJailInfo(jailName string) (*JailInfo, error) {
	result, err := f2bc.sendCommand([]string{statusCommand, jailName})
	if err != nil {
		return nil, err
	}

	// fmt.Printf("Result: %#v - %v\n", result, result)

	currentlyFailedResult := 0
	totalFailedResult := 0
	currentlyBannedResult := 0
	totalBannedResult := 0

	if getInfoTuple, getInfoOk := result.(*types.Tuple); getInfoOk {
		if infoList, infoListOk := getInfoTuple.Get(1).(*types.List); infoListOk {
			if infoList.Len() == 2 {
				if filterEntry, filterEntryOk := infoList.Get(0).(*types.Tuple); filterEntryOk {
					if filterTupleKey, filterTupleKeyOk := filterEntry.Get(0).(string); filterTupleKeyOk {
						if filterTupleKey == "Filter" {
							if filterList, filterListOk := filterEntry.Get(1).(*types.List); filterListOk {
								if currentlyFailedTuple, currentlyFailedTupleOk := filterList.Get(0).(*types.Tuple); currentlyFailedTupleOk {
									if currentlyFailedKey, currentlyFailedKeyOk := currentlyFailedTuple.Get(0).(string); currentlyFailedKeyOk {
										if currentlyFailedKey == "Currently failed" {
											if currentlyFailed, currentlyFailedOk := currentlyFailedTuple.Get(1).(int); currentlyFailedOk {
												currentlyFailedResult = currentlyFailed
											}
										}
									}
								}
								if totalFailedTuple, totalFailedTupleOk := filterList.Get(1).(*types.Tuple); totalFailedTupleOk {
									if totalFailedKey, totalFailedKeyOk := totalFailedTuple.Get(0).(string); totalFailedKeyOk {
										if totalFailedKey == "Total failed" {
											if totalFailed, totalFailedOk := totalFailedTuple.Get(1).(int); totalFailedOk {
												totalFailedResult = totalFailed
											}
										}
									}
								}
							}
						}
					}
				}
				if actionsEntry, actionsEntryOk := infoList.Get(1).(*types.Tuple); actionsEntryOk {
					if actionsTupleKey, actionsTupleKeyOk := actionsEntry.Get(0).(string); actionsTupleKeyOk {
						if actionsTupleKey == "Actions" {
							if actionsList, actionsListOk := actionsEntry.Get(1).(*types.List); actionsListOk {
								if currentlyBannedTuple, currentlyBannedTupleOk := actionsList.Get(0).(*types.Tuple); currentlyBannedTupleOk {
									if currentlyBannedKey, currentlyBannedKeyOk := currentlyBannedTuple.Get(0).(string); currentlyBannedKeyOk {
										if currentlyBannedKey == "Currently banned" {
											if currentlyBanned, currentlyBannedOk := currentlyBannedTuple.Get(1).(int); currentlyBannedOk {
												currentlyBannedResult = currentlyBanned
											}
										}
									}
								}
								if totalBannedTuple, totalBannedTupleOk := actionsList.Get(1).(*types.Tuple); totalBannedTupleOk {
									if totalBannedKey, totalBannedKeyOk := totalBannedTuple.Get(0).(string); totalBannedKeyOk {
										if totalBannedKey == "Total banned" {
											if totalBanned, totalBannedOk := totalBannedTuple.Get(1).(int); totalBannedOk {
												totalBannedResult = totalBanned
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}

	return &JailInfo{
		CurrentlyFailed: currentlyFailedResult,
		TotalFailed:     totalFailedResult,
		CurrentlyBanned: currentlyBannedResult,
		TotalBanned:     totalBannedResult,
	}, nil
}

func (f2bc *Fail2BanClient) GetBanned(jailName string) (*JailEntry, error) {
	var bannedEntries []*BanEntry
	result, err := f2bc.sendCommand([]string{getCommand, jailName, "banip", "--with-time"})
	if err != nil {
		return nil, err
	}

	if getBanTuple, getBanOk := result.(*types.Tuple); getBanOk {
		if banList, banListOk := getBanTuple.Get(1).(*types.List); banListOk {
			banListLen := banList.Len()
			for index := 0; index < banListLen; index++ {
				if listEnty, listEntyOk := banList.Get(index).(string); listEntyOk {
					re := regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3}) \t(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \+ (\d+) = (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$`)

					matches := re.FindStringSubmatch(listEnty)
					if matches == nil {
						return nil, errors.New("could not parse banned IPs entry")
					}

					layout := "2006-01-02 15:04:05" // reference layout

					bannedAt, bannedAtErr := time.Parse(layout, matches[2])
					if bannedAtErr != nil {
						return nil, bannedAtErr
					}

					banEndsAt, banEndsAtErr := time.Parse(layout, matches[4])
					if banEndsAtErr != nil {
						return nil, banEndsAtErr
					}

					ipAddress := matches[1]
					currenPenalty := matches[3]

					banEntry := &BanEntry{
						Address:       ipAddress,
						BannedAt:      bannedAt,
						CurrenPenalty: currenPenalty,
						BanEndsAt:     banEndsAt,
						JailName:      jailName,
					}

					bannedEntries = append(bannedEntries, banEntry)
				}
			}
		}
	}

	return &JailEntry{Name: jailName, BannedEntries: bannedEntries}, nil
}

func (f2bc *Fail2BanClient) sendCommand(command []string) (interface{}, error) {
	err := f2bc.write(command)
	if err != nil {
		return nil, err
	}
	return f2bc.read()
}

func (f2bc *Fail2BanClient) write(command []string) error {
	f2bc.mutex.Lock()
	defer f2bc.mutex.Unlock()
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
	f2bc.mutex.RLock()
	defer f2bc.mutex.RUnlock()
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
