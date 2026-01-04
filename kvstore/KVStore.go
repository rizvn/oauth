package kvstore

type KVStore interface {
	Get(key string) string
	Put(key, value string)
	PutWithTTL(key, value string, ttlSeconds int)
	Del(key string)

	Init()
}
