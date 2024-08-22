package infuzu

import (
	"fmt"
	"reflect"
	"sync"
	"time"
)

type cacheEntry struct {
	Data       interface{}
	ExpiryTime int64
}

type CacheSystem struct {
	cache                map[string]*cacheEntry
	DefaultFetchFunction interface{}
	DefaultExpiryTime    int64
	MaxSize              int
	hits                 int
	misses               int
	mutex                sync.Mutex
}

func NewCacheSystem(defaultFetchFunction interface{}, defaultExpiryTime int64, maxSize int) *CacheSystem {
	return &CacheSystem{
		cache:                make(map[string]*cacheEntry),
		DefaultFetchFunction: defaultFetchFunction,
		DefaultExpiryTime:    defaultExpiryTime,
		MaxSize:              maxSize,
		mutex:                sync.Mutex{},
	}
}

func (cs *CacheSystem) Get(
	cacheKeyName string,
	forceNew bool,
	specializedFetchFunction interface{},
	specializedExpiryTime int64,
	args ...interface{},
) (interface{}, error) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	cs.cleanup()
	currentTime := time.Now().Unix()
	if !forceNew {
		if entry, exists := cs.cache[cacheKeyName]; exists {
			if entry.ExpiryTime > currentTime {
				cs.hits++
				return entry.Data, nil
			}
		}
	}

	cs.misses++
	fetchFunction := specializedFetchFunction
	if fetchFunction == nil {
		fetchFunction = cs.DefaultFetchFunction
	}
	data, err := callFunction(fetchFunction, args...)
	if err != nil {
		return data, err
	}
	expiryTime := cs.DefaultExpiryTime
	if specializedExpiryTime != 0 {
		expiryTime = specializedExpiryTime
	}
	cs.cache[cacheKeyName] = &cacheEntry{
		Data:       data,
		ExpiryTime: currentTime + expiryTime,
	}
	cs.ensureMaxSize()
	return data, nil
}

func callFunction(fn interface{}, args ...interface{}) (interface{}, error) {
	f := reflect.ValueOf(fn)
	if len(args) != f.Type().NumIn() {
		return nil, fmt.Errorf("required %d arguments but got %d", f.Type().NumIn(), len(args))
	}
	in := make([]reflect.Value, len(args))
	for k, param := range args {
		in[k] = reflect.ValueOf(param)
	}
	out := f.Call(in)
	if len(out) < 1 || len(out) > 2 {
		return nil, fmt.Errorf("invalid number of return values: %d", len(out))
	}
	returnValue := out[0].Interface()
	if len(out) == 2 {
		if err, ok := out[1].Interface().(error); ok {
			return nil, err
		}
	}
	return returnValue, nil
}

func (cs *CacheSystem) Remove(cacheKeyName string) {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	delete(cs.cache, cacheKeyName)
}

func (cs *CacheSystem) cleanup() {
	currentTime := time.Now().Unix()
	for key, entry := range cs.cache {
		if entry.ExpiryTime <= currentTime {
			delete(cs.cache, key)
		}
	}
}

func (cs *CacheSystem) ensureMaxSize() {
	if cs.MaxSize > 0 && len(cs.cache) > cs.MaxSize {
		for key := range cs.cache {
			delete(cs.cache, key)
			if len(cs.cache) <= cs.MaxSize {
				break
			}
		}
	}
}

func (cs *CacheSystem) GetStats() map[string]int {
	cs.mutex.Lock()
	defer cs.mutex.Unlock()
	return map[string]int{
		"hits":   cs.hits,
		"misses": cs.misses,
		"size":   len(cs.cache),
	}
}
