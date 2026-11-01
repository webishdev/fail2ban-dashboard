package store

import (
	"sort"
	"sync"
	"time"

	"github.com/gofiber/fiber/v3/log"
	client "github.com/webishdev/fail2ban-dashboard/fail2ban-client"
	"github.com/webishdev/fail2ban-dashboard/models"
)

type UpdateHandler func()

type DataStore struct {
	mutex         sync.RWMutex
	ticker        *time.Ticker
	f2bc          *client.Fail2BanClient
	addressToJail map[string][]string
	jails         map[string]*models.JailEntry
	jailInfos     map[string]*models.JailInfo
	handlers      []UpdateHandler
}

func NewDataStore(f2bc *client.Fail2BanClient, refreshSeconds int) *DataStore {
	if f2bc == nil {
		return &DataStore{}
	}
	dataStore := &DataStore{
		ticker:        time.NewTicker(time.Duration(refreshSeconds) * time.Second),
		f2bc:          f2bc,
		addressToJail: make(map[string][]string),
		jails:         make(map[string]*models.JailEntry),
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
	dataStore.jails = make(map[string]*models.JailEntry)
	dataStore.jailInfos = make(map[string]*models.JailInfo)
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
	dataStore.notifyHandlers()
}

func (dataStore *DataStore) notifyHandlers() {
	for _, handler := range dataStore.handlers {
		go handler()
	}
}

func (dataStore *DataStore) RegisterUpdateHandler(handler UpdateHandler) {
	dataStore.mutex.Lock()
	defer dataStore.mutex.Unlock()
	dataStore.handlers = append(dataStore.handlers, handler)
}

func (dataStore *DataStore) Start() {
	if dataStore.f2bc == nil {
		return
	}
	time.AfterFunc(2*time.Second, func() {
		go dataStore.start()
	})

}

func (dataStore *DataStore) GetJails() []models.Jail {
	dataStore.mutex.RLock()
	defer dataStore.mutex.RUnlock()
	keys := make([]string, 0, len(dataStore.jails))
	for key := range dataStore.jails {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	jails := make([]models.Jail, len(dataStore.jails))
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

func (dataStore *DataStore) GetJailByName(jailName string) (models.Jail, bool) {
	dataStore.mutex.RLock()
	defer dataStore.mutex.RUnlock()
	if dataStore.jails[jailName] != nil && dataStore.jailInfos[jailName] != nil {
		jailEntry := dataStore.jails[jailName]
		jailInfo := dataStore.jailInfos[jailName]
		jail := createJail(jailEntry, jailInfo)
		return jail, true
	}
	return models.Jail{}, false
}

func createJail(entry *models.JailEntry, info *models.JailInfo) models.Jail {
	result := models.Jail{}
	if entry != nil {
		result.Name = entry.Name
		if entry.BannedEntries != nil {
			banEntries := make([]models.BanEntry, len(entry.BannedEntries))
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
