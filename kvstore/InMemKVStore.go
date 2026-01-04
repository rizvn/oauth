package kvstore

type InMemKVStore struct {
	//Temporary store for refresh tokens, key is access token jti
	data map[string]string
}

func (r *InMemKVStore) Init() {
	r.data = make(map[string]string)
}

func (r *InMemKVStore) Get(key string) string {
	value, ok := r.data[key]
	if !ok {
		return ""
	}
	return value
}

func (r *InMemKVStore) Put(key, value string) {
	r.data[key] = value
}

func (r *InMemKVStore) PutWithTTL(key, value string, ttlSeconds int) {
	r.Put(key, value)
}

func (r *InMemKVStore) Del(key string) {
	delete(r.data, key)
}
