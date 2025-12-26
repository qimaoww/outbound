package shadowsocks

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"github.com/qimaoww/outbound/common"
	"github.com/qimaoww/outbound/pool"
	"golang.org/x/crypto/hkdf"
	"lukechampine.com/blake3"
)

const (
	ss2022Context = "shadowsocks 2022 session subkey"
)

func isShadowsocks2022(method string) bool {
	return strings.HasPrefix(method, "2022-blake3-")
}

func deriveMasterKey(method, password string, keyLen int) ([]byte, error) {
	if !isShadowsocks2022(method) {
		return common.EVPBytesToKey(password, keyLen), nil
	}
	key, err := decodeBase64Key(password, keyLen)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func decodeBase64Key(password string, keyLen int) ([]byte, error) {
	if password == "" {
		return nil, fmt.Errorf("shadowsocks 2022 password is empty")
	}
	if decoded, err := base64.StdEncoding.DecodeString(password); err == nil {
		if len(decoded) != keyLen {
			return nil, fmt.Errorf("decoded key length %d does not match expected %d", len(decoded), keyLen)
		}
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(password); err == nil {
		if len(decoded) != keyLen {
			return nil, fmt.Errorf("decoded key length %d does not match expected %d", len(decoded), keyLen)
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("invalid base64 encoded password for shadowsocks 2022")
}

func deriveSessionSubKey(dst []byte, method string, masterKey []byte, salt []byte, info []byte) error {
	if len(dst) == 0 {
		return fmt.Errorf("empty subkey buffer")
	}
	if !isShadowsocks2022(method) {
		kdf := hkdf.New(sha1.New, masterKey, salt, info)
		_, err := io.ReadFull(kdf, dst)
		return err
	}
	if len(masterKey) != len(salt) {
		return fmt.Errorf("shadowsocks 2022 requires salt length %d equal to key length %d", len(salt), len(masterKey))
	}
	material := pool.Get(len(masterKey) + len(salt))
	defer pool.Put(material)
	copy(material, masterKey)
	copy(material[len(masterKey):], salt)
	blake3.DeriveKey(dst, ss2022Context, material)
	return nil
}
