package trojan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/protocol"
)

// MemoryAccount is an account type converted from Account.
type MemoryAccount struct {
	Password string
	Key      []byte

	// Maximum number of concurrent connections allowed for this user. 0 means unlimited.
	MaxConcurrentConnections int32
	// Maximum upload speed in bytes per second. 0 means unlimited.
	MaxUploadSpeed int64
	// Maximum download speed in bytes per second. 0 means unlimited.
	MaxDownloadSpeed int64
}

// AsAccount implements protocol.AsAccount.
func (a *Account) AsAccount() (protocol.Account, error) {
	password := a.GetPassword()
	key := hexSha224(password)
	return &MemoryAccount{
		Password:                 password,
		Key:                      key,
		MaxConcurrentConnections: a.MaxConcurrentConnections,
		MaxUploadSpeed:           a.MaxUploadSpeed,
		MaxDownloadSpeed:         a.MaxDownloadSpeed,
	}, nil
}

// Equals implements protocol.Account.Equals().
func (a *MemoryAccount) Equals(another protocol.Account) bool {
	if account, ok := another.(*MemoryAccount); ok {
		return a.Password == account.Password
	}
	return false
}

func (a *MemoryAccount) ToProto() proto.Message {
	return &Account{
		Password:                 a.Password,
		MaxConcurrentConnections: a.MaxConcurrentConnections,
		MaxUploadSpeed:           a.MaxUploadSpeed,
		MaxDownloadSpeed:         a.MaxDownloadSpeed,
	}
}

func hexSha224(password string) []byte {
	buf := make([]byte, 56)
	hash := sha256.New224()
	common.Must2(hash.Write([]byte(password)))
	hex.Encode(buf, hash.Sum(nil))
	return buf
}

func hexString(data []byte) string {
	str := ""
	for _, v := range data {
		str += fmt.Sprintf("%02x", v)
	}
	return str
}
