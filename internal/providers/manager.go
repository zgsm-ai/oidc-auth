package providers

import (
	"sync"
)

var (
	managerInstance *OAuthManager
	managerOnce     sync.Once
)

func GetManager() *OAuthManager {
	managerOnce.Do(func() {
		managerInstance = NewOAuthManager()
		managerInstance.RegisterFactory("casdoor", NewCasdoorFactory())
	})
	return managerInstance
}

func InitializeProviders(configs map[string]*ProviderConfig) {
	manager := GetManager()
	for name, config := range configs {
		manager.SetConfig(name, config)
	}
}
