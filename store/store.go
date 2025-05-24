package store

import (
	"github.com/gofiber/fiber/v2/log"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"sort"
	"sync"
	"time"
)

type DataStore struct {
	mutex         sync.RWMutex
	ticker        *time.Ticker
	f2bc          *client.Fail2BanClient
	addressToJail map[string][]string
	jails         map[string]*client.JailEntry
}

func NewDataStore(f2bc *client.Fail2BanClient) *DataStore {
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
		log.Info("Fetching fail2ban data")
		names, err := dataStore.f2bc.GetJailNames()
		if err != nil {
			break
		}
		dataStore.mutex.Lock()
		dataStore.jails = make(map[string]*client.JailEntry)
		for _, jailName := range names {
			jailEntry, getErr := dataStore.f2bc.GetBanned(jailName)
			if getErr != nil {
				dataStore.mutex.Unlock()
				break
			}
			dataStore.jails[jailName] = jailEntry
		}
		dataStore.mutex.Unlock()
		<-dataStore.ticker.C
	}
}

func (dataStore *DataStore) Start() {
	time.AfterFunc(2*time.Second, func() {
		go dataStore.start()
	})

}

func (dataStore *DataStore) GetJails() []client.StaticJailEntry {
	dataStore.mutex.RLock()
	defer dataStore.mutex.RUnlock()
	keys := make([]string, 0, len(dataStore.jails))
	for key := range dataStore.jails {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	jails := make([]client.StaticJailEntry, len(dataStore.jails))
	index := 0
	for _, key := range keys {
		jailEntry := dataStore.jails[key]
		jails[index] = jailEntry.Copy()
		index++
	}
	return jails
}

func (dataStore *DataStore) GetJailsByName(jailName string) (client.StaticJailEntry, bool) {
	dataStore.mutex.RLock()
	defer dataStore.mutex.RUnlock()
	if dataStore.jails[jailName] != nil {
		return dataStore.jails[jailName].Copy(), true
	}
	return client.StaticJailEntry{}, false
}
