package fail2ban_client

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2/log"
	ogórek "github.com/kisielk/og-rek"
	"github.com/nlpodyssey/gopickle/pickle"
	"github.com/nlpodyssey/gopickle/types"
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
	log.Tracef("Attempting to connect to fail2ban socket at %s", address)
	socket, err := net.Dial("unix", address)
	if err != nil {
		log.Errorf("Failed to connect to fail2ban socket at %s: %v", address, err)
		return nil, err
	}

	log.Debugf("Successfully connected to fail2ban socket at %s", address)
	encoder := ogórek.NewEncoder(socket)

	return &Fail2BanClient{
		socket:  socket,
		encoder: encoder,
	}, nil
}

func (f2bc *Fail2BanClient) GetVersion() (string, error) {
	log.Trace("GetVersion: Fetching fail2ban version")
	result, err := f2bc.sendCommand([]string{versionCommand})
	if err != nil {
		log.Errorf("GetVersion: Failed to get version: %v", err)
		return "", err
	}

	log.Tracef("GetVersion: Received result type: %T", result)
	if versionTuple, tupleOk := result.(*types.Tuple); tupleOk {
		if versionStr, versionOk := versionTuple.Get(1).(string); versionOk {
			log.Debugf("GetVersion: Successfully retrieved version: %s", versionStr)
			return versionStr, nil
		}
	}

	log.Error("GetVersion: Failed to parse version from response")
	return "", errors.New("fetching version failed")
}

func (f2bc *Fail2BanClient) GetJailNames() ([]string, error) {
	log.Trace("GetJailNames: Fetching jail names")
	result, err := f2bc.sendCommand([]string{statusCommand})
	if err != nil {
		log.Errorf("GetJailNames: Failed to get status: %v", err)
		return []string{}, err
	}

	log.Tracef("GetJailNames: Received result type: %T", result)
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
								log.Errorf("GetJailNames: Jail count mismatch - expected %d, got %d", expectedJailCount, len(jailNames))
								return []string{}, errors.New("number of jails did not match")
							}
							log.Debugf("GetJailNames: Successfully retrieved %d jails: %v", len(jailNames), jailNames)
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
	log.Tracef("GetJailInfo: Fetching info for jail '%s'", jailName)
	result, err := f2bc.sendCommand([]string{statusCommand, jailName})
	if err != nil {
		log.Errorf("GetJailInfo: Failed to get info for jail '%s': %v", jailName, err)
		return nil, err
	}

	log.Tracef("GetJailInfo: Received result type: %T", result)

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

	jailInfo := &JailInfo{
		CurrentlyFailed: currentlyFailedResult,
		TotalFailed:     totalFailedResult,
		CurrentlyBanned: currentlyBannedResult,
		TotalBanned:     totalBannedResult,
	}
	log.Debugf("GetJailInfo: Successfully retrieved info for jail '%s': Failed=%d/%d, Banned=%d/%d",
		jailName, currentlyFailedResult, totalFailedResult, currentlyBannedResult, totalBannedResult)
	return jailInfo, nil
}

func (f2bc *Fail2BanClient) GetBanned(jailName string) (*JailEntry, error) {
	log.Tracef("GetBanned: Fetching banned IPs for jail '%s'", jailName)
	var bannedEntries []*BanEntry
	result, err := f2bc.sendCommand([]string{getCommand, jailName, "banip", "--with-time"})
	if err != nil {
		log.Errorf("GetBanned: Failed to get banned IPs for jail '%s': %v", jailName, err)
		return nil, err
	}

	log.Tracef("GetBanned: Received result type: %T", result)

	if getBanTuple, getBanOk := result.(*types.Tuple); getBanOk {
		if banList, banListOk := getBanTuple.Get(1).(*types.List); banListOk {
			banListLen := banList.Len()
			for index := 0; index < banListLen; index++ {
				if listEnty, listEntyOk := banList.Get(index).(string); listEntyOk {
					log.Tracef("GetBanned: Parsing ban entry: %s", listEnty)
					re := regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3}) \t(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \+ (\d+) = (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$`)

					matches := re.FindStringSubmatch(listEnty)
					if matches == nil {
						log.Errorf("GetBanned: Failed to parse ban entry: %s", listEnty)
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

	log.Debugf("GetBanned: Successfully retrieved %d banned IPs for jail '%s'", len(bannedEntries), jailName)
	return &JailEntry{Name: jailName, BannedEntries: bannedEntries}, nil
}

func (f2bc *Fail2BanClient) sendCommand(command []string) (interface{}, error) {
	log.Tracef("Sending command to fail2ban: %v", command)
	err := f2bc.write(command)
	if err != nil {
		log.Errorf("Failed to write command %v: %v", command, err)
		return nil, err
	}

	result, err := f2bc.read()
	if err != nil {
		log.Errorf("Failed to read response for command %v: %v", command, err)
		return nil, err
	}

	log.Tracef("Command %v completed successfully", command)
	return result, nil
}

func (f2bc *Fail2BanClient) write(command []string) error {
	f2bc.mutex.Lock()
	defer f2bc.mutex.Unlock()

	log.Tracef("Writing command to socket: %v", command)
	err := f2bc.encoder.Encode(command)
	if err != nil {
		log.Errorf("Failed to encode command %v: %v", command, err)
		return err
	}

	log.Tracef("Writing command terminator: %s", commandTerminator)
	_, err = f2bc.socket.Write([]byte(commandTerminator))
	if err != nil {
		log.Errorf("Failed to write command terminator: %v", err)
		return err
	}

	log.Tracef("Command written successfully: %v", command)
	return nil
}

func (f2bc *Fail2BanClient) read() (interface{}, error) {
	f2bc.mutex.RLock()
	defer f2bc.mutex.RUnlock()

	log.Trace("Starting to read response from socket")
	reader := bufio.NewReader(f2bc.socket)

	data := []byte{}
	readIterations := 0
	for {
		buf := make([]byte, socketReadBufferSize)
		n, err := reader.Read(buf)
		if err != nil {
			log.Errorf("Error reading from socket after %d bytes: %v", len(data), err)
			return nil, err
		}
		readIterations++
		data = append(data, buf[:n]...)
		log.Tracef("Read iteration %d: received %d bytes, total %d bytes", readIterations, n, len(data))

		containsTerminator := bytes.Contains(data, []byte(commandTerminator))
		if containsTerminator {
			log.Tracef("Command terminator found after %d iterations, %d total bytes", readIterations, len(data))
			break
		}
	}

	log.Tracef("Raw response data (first 200 bytes): %q", string(data[:min(200, len(data))]))

	bufReader := bytes.NewReader(data)
	unpickler := pickle.NewUnpickler(bufReader)

	unpickler.FindClass = func(module, name string) (interface{}, error) {
		log.Tracef("Unpickler FindClass called: module=%s, name=%s", module, name)
		if (module == "builtins" || module == "__builtin__") && name == "str" {
			return &Py_builtins_str{}, nil
		}
		return nil, fmt.Errorf("class not found: [%s] %s", module, name)
	}

	log.Trace("Unpickling response data")
	result, err := unpickler.Load()
	if err != nil {
		log.Errorf("Failed to unpickle response: %v", err)
		return nil, err
	}

	log.Tracef("Successfully unpickled response: %T", result)
	return result, nil
}
