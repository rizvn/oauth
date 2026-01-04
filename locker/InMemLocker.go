package locker

import "sync"

type InMemLocker struct {
	locks sync.Map
}

func (r *InMemLocker) Init() {
}

func (r *InMemLocker) Lock(key string) {
	lockIface, _ := r.locks.LoadOrStore(key, &sync.Mutex{})
	lock := lockIface.(*sync.Mutex)
	lock.Lock()
}

func (r *InMemLocker) Unlock(key string) {
	lockIface, ok := r.locks.Load(key)
	if !ok {
		return
	}
	lock := lockIface.(*sync.Mutex)
	lock.Unlock()
	r.locks.Delete(key)
}
