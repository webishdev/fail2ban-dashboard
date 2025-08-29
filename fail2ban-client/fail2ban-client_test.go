package fail2ban_client

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/kisielk/og-rek"
)

// Mock connection for testing
type mockConn struct {
	readData  []byte
	writeData []byte
	readErr   error
	writeErr  error
	closed    bool
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// Mock Tuple for testing
type mockTuple struct {
	items []interface{}
}

func (m *mockTuple) Get(index int) interface{} {
	if index < 0 || index >= len(m.items) {
		return nil
	}
	return m.items[index]
}

// Mock List for testing
type mockList struct {
	items []interface{}
}

func (m *mockList) Get(index int) interface{} {
	if index < 0 || index >= len(m.items) {
		return nil
	}
	return m.items[index]
}

func (m *mockList) Len() int {
	return len(m.items)
}

// Helper function to create a mock client
func createMockClient(readData []byte, readErr error, writeErr error) *Fail2BanClient {
	mockSocket := &mockConn{
		readData: readData,
		readErr:  readErr,
		writeErr: writeErr,
	}

	encoder := ogórek.NewEncoder(mockSocket)

	return &Fail2BanClient{
		socket:  mockSocket,
		encoder: encoder,
	}
}

// Helper function to create pickle data for testing
func createPickleData(data interface{}) []byte {
	var buf bytes.Buffer
	encoder := ogórek.NewEncoder(&buf)
	encoder.Encode(data)
	buf.WriteString("<F2B_END_COMMAND>")
	return buf.Bytes()
}

// Mock client with controlled responses
type mockFail2BanClient struct {
	*Fail2BanClient
	mockVersionResponse string
	mockVersionError    error
	mockResponse        interface{}
	mockError           error
}

func (m *mockFail2BanClient) GetVersion() (string, error) {
	if m.mockVersionError != nil {
		return "", m.mockVersionError
	}
	return m.mockVersionResponse, nil
}

func (m *mockFail2BanClient) GetJailNames() ([]string, error) {
	result, err := m.sendCommand([]string{statusCommand})
	if err != nil {
		return []string{}, err
	}

	expectedJailCount := 0

	if statusTuple, tupleOk := result.(*mockTuple); tupleOk {
		if statusList, listOk := statusTuple.Get(1).(*mockList); listOk {
			if numberOfJailsTuple, numberTupleOk := statusList.Get(0).(*mockTuple); numberTupleOk {
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
			if jailListTuple, jailListTupleOk := statusList.Get(1).(*mockTuple); jailListTupleOk {
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

func (m *mockFail2BanClient) GetJailInfo(jailName string) (*JailInfo, error) {
	result, err := m.sendCommand([]string{statusCommand, jailName})
	if err != nil {
		return nil, err
	}

	currentlyFailedResult := 0
	totalFailedResult := 0
	currentlyBannedResult := 0
	totalBannedResult := 0

	if getInfoTuple, getInfoOk := result.(*mockTuple); getInfoOk {
		if infoList, infoListOk := getInfoTuple.Get(1).(*mockList); infoListOk {
			if infoList.Len() == 2 {
				if filterEntry, filterEntryOk := infoList.Get(0).(*mockTuple); filterEntryOk {
					if filterTupleKey, filterTupleKeyOk := filterEntry.Get(0).(string); filterTupleKeyOk {
						if filterTupleKey == "Filter" {
							if filterList, filterListOk := filterEntry.Get(1).(*mockList); filterListOk {
								if currentlyFailedTuple, currentlyFailedTupleOk := filterList.Get(0).(*mockTuple); currentlyFailedTupleOk {
									if currentlyFailedKey, currentlyFailedKeyOk := currentlyFailedTuple.Get(0).(string); currentlyFailedKeyOk {
										if currentlyFailedKey == "Currently failed" {
											if currentlyFailed, currentlyFailedOk := currentlyFailedTuple.Get(1).(int); currentlyFailedOk {
												currentlyFailedResult = currentlyFailed
											}
										}
									}
								}
								if totalFailedTuple, totalFailedTupleOk := filterList.Get(1).(*mockTuple); totalFailedTupleOk {
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
				if actionsEntry, actionsEntryOk := infoList.Get(1).(*mockTuple); actionsEntryOk {
					if actionsTupleKey, actionsTupleKeyOk := actionsEntry.Get(0).(string); actionsTupleKeyOk {
						if actionsTupleKey == "Actions" {
							if actionsList, actionsListOk := actionsEntry.Get(1).(*mockList); actionsListOk {
								if currentlyBannedTuple, currentlyBannedTupleOk := actionsList.Get(0).(*mockTuple); currentlyBannedTupleOk {
									if currentlyBannedKey, currentlyBannedKeyOk := currentlyBannedTuple.Get(0).(string); currentlyBannedKeyOk {
										if currentlyBannedKey == "Currently banned" {
											if currentlyBanned, currentlyBannedOk := currentlyBannedTuple.Get(1).(int); currentlyBannedOk {
												currentlyBannedResult = currentlyBanned
											}
										}
									}
								}
								if totalBannedTuple, totalBannedTupleOk := actionsList.Get(1).(*mockTuple); totalBannedTupleOk {
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

func (m *mockFail2BanClient) GetBanned(jailName string) (*JailEntry, error) {
	var bannedEntries []*BanEntry
	result, err := m.sendCommand([]string{getCommand, jailName, "banip", "--with-time"})
	if err != nil {
		return nil, err
	}

	if getBanTuple, getBanOk := result.(*mockTuple); getBanOk {
		if banList, banListOk := getBanTuple.Get(1).(*mockList); banListOk {
			banListLen := banList.Len()
			for index := 0; index < banListLen; index++ {
				if listEntry, listEntryOk := banList.Get(index).(string); listEntryOk {
					re := regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3}) \t(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \+ (\d+) = (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})$`)

					matches := re.FindStringSubmatch(listEntry)
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

func (m *mockFail2BanClient) sendCommand(command []string) (interface{}, error) {
	if m.mockError != nil {
		return nil, m.mockError
	}
	return m.mockResponse, nil
}

func TestNewFail2BanClient(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{
			name:    "invalid socket path",
			address: "/non/existent/socket",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewFail2BanClient(tt.address)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewFail2BanClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if client != nil {
				client.socket.Close()
			}
		})
	}
}

func TestFail2BanClient_GetVersion(t *testing.T) {
	tests := []struct {
		name        string
		mockVersion string
		mockErr     error
		want        string
		wantErr     bool
	}{
		{
			name:        "successful version fetch",
			mockVersion: "1.0.0",
			want:        "1.0.0",
			wantErr:     false,
		},
		{
			name:        "version fetch error",
			mockVersion: "",
			mockErr:     errors.New("connection error"),
			want:        "",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockFail2BanClient{
				Fail2BanClient:      createMockClient(nil, nil, nil),
				mockVersionResponse: tt.mockVersion,
				mockVersionError:    tt.mockErr,
			}

			got, err := client.GetVersion()

			if (err != nil) != tt.wantErr {
				t.Errorf("GetVersion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetVersion() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFail2BanClient_GetJailNames(t *testing.T) {
	tests := []struct {
		name     string
		response interface{}
		mockErr  error
		want     []string
		wantErr  bool
	}{
		{
			name: "successful jail names fetch",
			response: &mockTuple{
				items: []interface{}{
					nil,
					&mockList{
						items: []interface{}{
							&mockTuple{items: []interface{}{"Number of jail", 2}},
							&mockTuple{items: []interface{}{"Jail list", "jail1, jail2"}},
						},
					},
				},
			},
			want:    []string{"jail1", "jail2"},
			wantErr: false,
		},
		{
			name: "jail count mismatch",
			response: &mockTuple{
				items: []interface{}{
					nil,
					&mockList{
						items: []interface{}{
							&mockTuple{items: []interface{}{"Number of jail", 1}},
							&mockTuple{items: []interface{}{"Jail list", "jail1, jail2"}},
						},
					},
				},
			},
			want:    []string{},
			wantErr: true,
		},
		{
			name:     "sendCommand error",
			response: nil,
			mockErr:  errors.New("connection error"),
			want:     []string{},
			wantErr:  true,
		},
		{
			name:     "invalid response format",
			response: "invalid",
			want:     []string{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockFail2BanClient{
				Fail2BanClient: createMockClient(nil, nil, nil),
				mockResponse:   tt.response,
				mockError:      tt.mockErr,
			}

			got, err := client.GetJailNames()

			if (err != nil) != tt.wantErr {
				t.Errorf("GetJailNames() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetJailNames() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFail2BanClient_GetJailInfo(t *testing.T) {
	tests := []struct {
		name     string
		jailName string
		response interface{}
		mockErr  error
		want     *JailInfo
		wantErr  bool
	}{
		{
			name:     "successful jail info fetch",
			jailName: "test-jail",
			response: &mockTuple{
				items: []interface{}{
					nil,
					&mockList{
						items: []interface{}{
							&mockTuple{
								items: []interface{}{
									"Filter",
									&mockList{
										items: []interface{}{
											&mockTuple{items: []interface{}{"Currently failed", 5}},
											&mockTuple{items: []interface{}{"Total failed", 100}},
										},
									},
								},
							},
							&mockTuple{
								items: []interface{}{
									"Actions",
									&mockList{
										items: []interface{}{
											&mockTuple{items: []interface{}{"Currently banned", 2}},
											&mockTuple{items: []interface{}{"Total banned", 50}},
										},
									},
								},
							},
						},
					},
				},
			},
			want: &JailInfo{
				CurrentlyFailed: 5,
				TotalFailed:     100,
				CurrentlyBanned: 2,
				TotalBanned:     50,
			},
			wantErr: false,
		},
		{
			name:     "sendCommand error",
			jailName: "test-jail",
			response: nil,
			mockErr:  errors.New("connection error"),
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "empty response",
			jailName: "test-jail",
			response: &mockTuple{items: []interface{}{nil, &mockList{items: []interface{}{}}}},
			want: &JailInfo{
				CurrentlyFailed: 0,
				TotalFailed:     0,
				CurrentlyBanned: 0,
				TotalBanned:     0,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockFail2BanClient{
				Fail2BanClient: createMockClient(nil, nil, nil),
				mockResponse:   tt.response,
				mockError:      tt.mockErr,
			}

			got, err := client.GetJailInfo(tt.jailName)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetJailInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetJailInfo() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFail2BanClient_GetBanned(t *testing.T) {
	tests := []struct {
		name     string
		jailName string
		response interface{}
		mockErr  error
		want     *JailEntry
		wantErr  bool
	}{
		{
			name:     "successful banned entries fetch",
			jailName: "test-jail",
			response: &mockTuple{
				items: []interface{}{
					nil,
					&mockList{
						items: []interface{}{
							"192.168.1.100 \t2023-08-29 10:30:00 + 600 = 2023-08-29 10:40:00",
							"10.0.0.50 \t2023-08-29 11:00:00 + 1800 = 2023-08-29 11:30:00",
						},
					},
				},
			},
			want: &JailEntry{
				Name: "test-jail",
				BannedEntries: []*BanEntry{
					{
						Address:       "192.168.1.100",
						BannedAt:      time.Date(2023, 8, 29, 10, 30, 0, 0, time.UTC),
						CurrenPenalty: "600",
						BanEndsAt:     time.Date(2023, 8, 29, 10, 40, 0, 0, time.UTC),
						JailName:      "test-jail",
					},
					{
						Address:       "10.0.0.50",
						BannedAt:      time.Date(2023, 8, 29, 11, 0, 0, 0, time.UTC),
						CurrenPenalty: "1800",
						BanEndsAt:     time.Date(2023, 8, 29, 11, 30, 0, 0, time.UTC),
						JailName:      "test-jail",
					},
				},
			},
			wantErr: false,
		},
		{
			name:     "invalid entry format",
			jailName: "test-jail",
			response: &mockTuple{
				items: []interface{}{
					nil,
					&mockList{
						items: []interface{}{
							"invalid format",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name:     "sendCommand error",
			jailName: "test-jail",
			response: nil,
			mockErr:  errors.New("connection error"),
			want:     nil,
			wantErr:  true,
		},
		{
			name:     "empty banned list",
			jailName: "test-jail",
			response: &mockTuple{
				items: []interface{}{
					nil,
					&mockList{items: []interface{}{}},
				},
			},
			want: &JailEntry{
				Name:          "test-jail",
				BannedEntries: []*BanEntry{},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &mockFail2BanClient{
				Fail2BanClient: createMockClient(nil, nil, nil),
				mockResponse:   tt.response,
				mockError:      tt.mockErr,
			}

			got, err := client.GetBanned(tt.jailName)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetBanned() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if got.Name != tt.want.Name {
				t.Errorf("GetBanned() name = %v, want %v", got.Name, tt.want.Name)
			}

			if len(got.BannedEntries) != len(tt.want.BannedEntries) {
				t.Errorf("GetBanned() entries count = %v, want %v", len(got.BannedEntries), len(tt.want.BannedEntries))
				return
			}

			for i, entry := range got.BannedEntries {
				wantEntry := tt.want.BannedEntries[i]
				if entry.Address != wantEntry.Address ||
					!entry.BannedAt.Equal(wantEntry.BannedAt) ||
					entry.CurrenPenalty != wantEntry.CurrenPenalty ||
					!entry.BanEndsAt.Equal(wantEntry.BanEndsAt) ||
					entry.JailName != wantEntry.JailName {
					t.Errorf("GetBanned() entry %d = %+v, want %+v", i, entry, wantEntry)
				}
			}
		})
	}
}

func TestFail2BanClient_write(t *testing.T) {
	tests := []struct {
		name     string
		command  []string
		writeErr error
		wantErr  bool
	}{
		{
			name:     "successful write",
			command:  []string{"status"},
			writeErr: nil,
			wantErr:  false,
		},
		{
			name:     "write error",
			command:  []string{"status"},
			writeErr: errors.New("write failed"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := createMockClient(nil, nil, tt.writeErr)
			err := client.write(tt.command)

			if (err != nil) != tt.wantErr {
				t.Errorf("write() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr {
				mockSocket := client.socket.(*mockConn)
				if !strings.Contains(string(mockSocket.writeData), "<F2B_END_COMMAND>") {
					t.Errorf("write() did not write command terminator")
				}
			}
		})
	}
}

func TestFail2BanClient_read(t *testing.T) {
	tests := []struct {
		name     string
		readData []byte
		readErr  error
		wantErr  bool
	}{
		{
			name:     "successful read",
			readData: createPickleData("test"),
			readErr:  nil,
			wantErr:  false,
		},
		{
			name:     "read error",
			readData: nil,
			readErr:  errors.New("read failed"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := createMockClient(tt.readData, tt.readErr, nil)
			_, err := client.read()

			if (err != nil) != tt.wantErr {
				t.Errorf("read() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestFail2BanClient_sendCommand(t *testing.T) {
	tests := []struct {
		name     string
		command  []string
		response interface{}
		readErr  error
		writeErr error
		wantErr  bool
	}{
		{
			name:     "successful command",
			command:  []string{"status"},
			response: "success",
			readErr:  nil,
			writeErr: nil,
			wantErr:  false,
		},
		{
			name:     "write error",
			command:  []string{"status"},
			response: nil,
			readErr:  nil,
			writeErr: errors.New("write failed"),
			wantErr:  true,
		},
		{
			name:     "read error",
			command:  []string{"status"},
			response: nil,
			readErr:  errors.New("read failed"),
			writeErr: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mockData []byte
			if tt.response != nil {
				mockData = createPickleData(tt.response)
			}

			client := createMockClient(mockData, tt.readErr, tt.writeErr)
			_, err := client.sendCommand(tt.command)

			if (err != nil) != tt.wantErr {
				t.Errorf("sendCommand() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBanEntry(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)

	entry := &BanEntry{
		Address:       "192.168.1.1",
		BannedAt:      now,
		CurrenPenalty: "3600",
		BanEndsAt:     later,
		JailName:      "sshd",
		CountryCode:   "US",
	}

	if entry.Address != "192.168.1.1" {
		t.Errorf("BanEntry Address = %v, want %v", entry.Address, "192.168.1.1")
	}

	if !entry.BannedAt.Equal(now) {
		t.Errorf("BanEntry BannedAt = %v, want %v", entry.BannedAt, now)
	}

	if entry.JailName != "sshd" {
		t.Errorf("BanEntry JailName = %v, want %v", entry.JailName, "sshd")
	}
}

func TestJailEntry(t *testing.T) {
	entry := &JailEntry{
		Name:          "test-jail",
		BannedEntries: []*BanEntry{},
	}

	if entry.Name != "test-jail" {
		t.Errorf("JailEntry Name = %v, want %v", entry.Name, "test-jail")
	}

	if len(entry.BannedEntries) != 0 {
		t.Errorf("JailEntry BannedEntries length = %v, want %v", len(entry.BannedEntries), 0)
	}
}

func TestJailInfo(t *testing.T) {
	info := &JailInfo{
		CurrentlyFailed: 5,
		TotalFailed:     100,
		CurrentlyBanned: 2,
		TotalBanned:     50,
	}

	if info.CurrentlyFailed != 5 {
		t.Errorf("JailInfo CurrentlyFailed = %v, want %v", info.CurrentlyFailed, 5)
	}

	if info.TotalFailed != 100 {
		t.Errorf("JailInfo TotalFailed = %v, want %v", info.TotalFailed, 100)
	}

	if info.CurrentlyBanned != 2 {
		t.Errorf("JailInfo CurrentlyBanned = %v, want %v", info.CurrentlyBanned, 2)
	}

	if info.TotalBanned != 50 {
		t.Errorf("JailInfo TotalBanned = %v, want %v", info.TotalBanned, 50)
	}
}
