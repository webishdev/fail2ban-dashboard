package store

import (
	"github.com/gofiber/fiber/v2/log"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"sort"
	"sync"
	"time"
)

type Jail struct {
	Name            string
	BannedCount     int
	BannedEntries   []client.BanEntry
	CurrentlyFailed int
	TotalFailed     int
	CurrentlyBanned int
	TotalBanned     int
}

type DataStore struct {
	mutex         sync.RWMutex
	ticker        *time.Ticker
	f2bc          *client.Fail2BanClient
	addressToJail map[string][]string
	jails         map[string]*client.JailEntry
	jailInfos     map[string]*client.JailInfo
}

func NewDataStore(f2bc *client.Fail2BanClient) *DataStore {
	if f2bc == nil {
		return &DataStore{}
	}
	dataStore := &DataStore{
		ticker:        time.NewTicker(30 * time.Second),
		f2bc:          f2bc,
		addressToJail: make(map[string][]string),
		jails:         make(map[string]*client.JailEntry),
	}

	return dataStore
}

func (dataStore *DataStore) start() {
	defer dataStore.ticker.Stop()
	for {
		log.Debug("Fetching fail2ban data")
		names, err := dataStore.f2bc.GetJailNames()
		if err != nil {
			break
		}
		dataStore.initialize(names)
		<-dataStore.ticker.C
	}
}

func (dataStore *DataStore) initialize(names []string) {
	dataStore.mutex.Lock()
	defer dataStore.mutex.Unlock()
	dataStore.jails = make(map[string]*client.JailEntry)
	dataStore.jailInfos = make(map[string]*client.JailInfo)
	for _, jailName := range names {
		jailEntry, getBannedErr := dataStore.f2bc.GetBanned(jailName)
		if getBannedErr != nil {
			break
		}
		jailInfo, getInfoErr := dataStore.f2bc.GetJailInfo(jailName)
		if getInfoErr != nil {
			break
		}

		dataStore.jails[jailName] = jailEntry
		dataStore.jailInfos[jailName] = jailInfo
	}
}

func (dataStore *DataStore) Start() {
	if dataStore.f2bc == nil {
		return
	}
	time.AfterFunc(2*time.Second, func() {
		go dataStore.start()
	})

}

func (dataStore *DataStore) GetJails() []Jail {
	dataStore.mutex.RLock()
	defer dataStore.mutex.RUnlock()
	keys := make([]string, 0, len(dataStore.jails))
	for key := range dataStore.jails {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	jails := make([]Jail, len(dataStore.jails))
	index := 0
	for _, key := range keys {
		jail, exists := dataStore.GetJailByName(key)
		if exists {
			jails[index] = jail
		}
		index++
	}
	return jails
}

func (dataStore *DataStore) GetJailByName(jailName string) (Jail, bool) {
	dataStore.mutex.RLock()
	defer dataStore.mutex.RUnlock()
	if dataStore.jails[jailName] != nil && dataStore.jailInfos[jailName] != nil {
		jailEntry := dataStore.jails[jailName]
		jailInfo := dataStore.jailInfos[jailName]
		jail := createJail(jailEntry, jailInfo)
		return jail, true
	}
	return Jail{}, false
}

func createJail(entry *client.JailEntry, info *client.JailInfo) Jail {
	result := Jail{}
	if entry != nil {
		result.Name = entry.Name
		if entry.BannedEntries != nil {
			banEntries := make([]client.BanEntry, len(entry.BannedEntries))
			for i, p := range entry.BannedEntries {
				if p != nil {
					banEntries[i] = *p // dereference the pointer
				}
			}
			result.BannedCount = len(banEntries)
			result.BannedEntries = banEntries
		}
	}

	if info != nil {
		result.CurrentlyFailed = info.CurrentlyFailed
		result.TotalFailed = info.TotalFailed
		result.CurrentlyBanned = info.CurrentlyBanned
		result.TotalBanned = info.TotalBanned
	}

	return result
}
