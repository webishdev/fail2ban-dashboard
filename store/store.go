package store

import (
	"fmt"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
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

	go dataStore.start()

	return dataStore
}

func (dataStore *DataStore) start() {
	defer dataStore.ticker.Stop()
	for {
		fmt.Println("fetching fail2ban data")
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

func (dataStore *DataStore) GetJails() []client.StaticJailEntry {
	dataStore.mutex.RLock()
	defer dataStore.mutex.RUnlock()
	jails := make([]client.StaticJailEntry, len(dataStore.jails))
	index := 0
	for _, jailEntry := range dataStore.jails {
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
