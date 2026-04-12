package ports

type Hasher interface {
	Hash(string) (string, error)
	Compare(string, string) (bool, error)
}
