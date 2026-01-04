package locker

type Locker interface {
	Lock(key string)
	Unlock(key string)
	Init()
}
