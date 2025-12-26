package shadowsocks

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"math"
	"sync"
	"time"

	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/qimaoww/outbound/ciphers"
	"github.com/qimaoww/outbound/common"
	"github.com/qimaoww/outbound/netproxy"
	"github.com/qimaoww/outbound/pkg/fastrand"
	"github.com/qimaoww/outbound/pool"
	"github.com/qimaoww/outbound/protocol"
)

const (
	TCPChunkMaxLen = (1 << (16 - 2)) - 1
)

var (
	ErrFailInitCipher = fmt.Errorf("fail to initiate cipher")
)

type TCPConn struct {
	netproxy.Conn
	metadata    protocol.Metadata
	cipherConf  *ciphers.CipherConf
	masterKey   []byte
	is2022      bool
	chunkLimit  int
	requestSalt []byte

	cipherRead  cipher.AEAD
	cipherWrite cipher.AEAD
	onceRead    bool
	onceWrite   bool
	nonceRead   []byte
	nonceWrite  []byte

	readMutex  sync.Mutex
	writeMutex sync.Mutex

	leftToRead  []byte
	indexToRead int

	bloom *disk_bloom.FilterGroup
	sg    SaltGenerator
}

type Key struct {
	CipherConf *ciphers.CipherConf
	MasterKey  []byte
	Method     string
}

func EncryptedPayloadLen(plainTextLen int, tagLen int) int {
	n := plainTextLen / TCPChunkMaxLen
	if plainTextLen%TCPChunkMaxLen > 0 {
		n++
	}
	return plainTextLen + n*(2+tagLen+tagLen)
}

func (c *TCPConn) encryptedPayloadLen(plainTextLen int) int {
	limit := c.chunkLimit
	n := plainTextLen / limit
	if plainTextLen%limit > 0 {
		n++
	}
	return plainTextLen + n*(2+c.cipherConf.TagLen+c.cipherConf.TagLen)
}

func NewTCPConn(conn netproxy.Conn, metadata protocol.Metadata, masterKey []byte, bloom *disk_bloom.FilterGroup) (crw *TCPConn, err error) {
	conf := ciphers.AeadCiphersConf[metadata.Cipher]
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid CipherConf")
	}
	sg, err := GetSaltGenerator(masterKey, conf.SaltLen)
	if err != nil {
		return nil, err
	}
	is2022 := isShadowsocks2022(metadata.Cipher)
	chunkLimit := TCPChunkMaxLen
	if is2022 {
		chunkLimit = math.MaxUint16
	}
	// DO NOT use pool here because Close() cannot interrupt the reading or writing, which will modify the value of the pool buffer.
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	c := TCPConn{
		Conn:       conn,
		metadata:   metadata,
		cipherConf: conf,
		masterKey:  key,
		is2022:     is2022,
		chunkLimit: chunkLimit,
		nonceRead:  make([]byte, conf.NonceLen),
		nonceWrite: make([]byte, conf.NonceLen),
		bloom:      bloom,
		sg:         sg,
	}
	if metadata.IsClient {
		time.AfterFunc(100*time.Millisecond, func() {
			// avoid the situation where the server sends messages first
			if _, err = c.Write(nil); err != nil {
				return
			}
		})
	}
	return &c, nil
}

func (c *TCPConn) Close() error {
	return c.Conn.Close()
}

func (c *TCPConn) Read(b []byte) (n int, err error) {
	c.readMutex.Lock()
	defer c.readMutex.Unlock()
	if c.is2022 {
		return c.read2022(b)
	}
	if !c.onceRead {
		var salt = pool.Get(c.cipherConf.SaltLen)
		defer pool.Put(salt)
		n, err = io.ReadFull(c.Conn, salt)
		if err != nil {
			return
		}
		if c.bloom != nil {
			if c.bloom.ExistOrAdd(salt) {
				err = protocol.ErrReplayAttack
				return
			}
		}
		//log.Warn("salt: %v", hex.EncodeToString(salt))
		subKey := pool.Get(c.cipherConf.KeyLen)
		defer pool.Put(subKey)
		if err = deriveSessionSubKey(subKey, c.metadata.Cipher, c.masterKey, salt, ciphers.ShadowsocksReusedInfo); err != nil {
			return
		}
		if err != nil {
			return
		}
		c.cipherRead, err = c.cipherConf.NewCipher(subKey)
		if err != nil {
			return 0, fmt.Errorf("%v: %w", ErrFailInitCipher, err)
		}
		c.onceRead = true
	}
	if c.indexToRead < len(c.leftToRead) {
		n = copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead >= len(c.leftToRead) {
			// Put the buf back
			pool.Put(c.leftToRead)
		}
		return n, nil
	}
	// Chunk
	chunk, err := c.readChunkFromPool()
	if err != nil {
		return 0, err
	}
	n = copy(b, chunk)
	if n < len(chunk) {
		// Wait for the next read
		c.leftToRead = chunk
		c.indexToRead = n
	} else {
		// Full reading. Put the buf back
		pool.Put(chunk)
	}
	return n, nil
}

func (c *TCPConn) read2022(b []byte) (int, error) {
	if !c.onceRead {
		if err := c.initRead2022(); err != nil {
			return 0, err
		}
	}
	if c.indexToRead < len(c.leftToRead) {
		n := copy(b, c.leftToRead[c.indexToRead:])
		c.indexToRead += n
		if c.indexToRead >= len(c.leftToRead) {
			pool.Put(c.leftToRead)
		}
		return n, nil
	}
	chunk, err := c.readChunkFromPool()
	if err != nil {
		return 0, err
	}
	n := copy(b, chunk)
	if n < len(chunk) {
		c.leftToRead = chunk
		c.indexToRead = n
	} else {
		pool.Put(chunk)
	}
	return n, nil
}

func (c *TCPConn) initRead2022() error {
	salt := pool.Get(c.cipherConf.SaltLen)
	defer pool.Put(salt)
	if _, err := io.ReadFull(c.Conn, salt); err != nil {
		return err
	}
	subKey := pool.Get(c.cipherConf.KeyLen)
	if err := deriveSessionSubKey(subKey, c.metadata.Cipher, c.masterKey, salt, ciphers.ShadowsocksReusedInfo); err != nil {
		pool.Put(subKey)
		return err
	}
	cipherRead, err := c.cipherConf.NewCipher(subKey)
	pool.Put(subKey)
	if err != nil {
		return fmt.Errorf("%v: %w", ErrFailInitCipher, err)
	}
	c.cipherRead = cipherRead
	headLen := 1 + 8 + c.cipherConf.SaltLen + 2
	headBuf := pool.Get(headLen + c.cipherConf.TagLen)
	defer pool.Put(headBuf)
	if _, err := io.ReadFull(c.Conn, headBuf); err != nil {
		return err
	}
	headPlain, err := c.cipherRead.Open(headBuf[:0], c.nonceRead, headBuf, nil)
	if err != nil || len(headPlain) != headLen {
		return protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	if headPlain[0] != 1 {
		return protocol.ErrFailAuth
	}
	ts := binary.BigEndian.Uint64(headPlain[1:9])
	if !validSS2022Timestamp(ts) {
		return protocol.ErrFailAuth
	}
	if len(c.requestSalt) == c.cipherConf.SaltLen {
		if !bytes.Equal(headPlain[9:9+c.cipherConf.SaltLen], c.requestSalt) {
			return protocol.ErrFailAuth
		}
	}
	firstPayloadLen := binary.BigEndian.Uint16(headPlain[headLen-2:])
	payloadBuf := pool.Get(int(firstPayloadLen) + c.cipherConf.TagLen)
	if _, err := io.ReadFull(c.Conn, payloadBuf); err != nil {
		pool.Put(payloadBuf)
		return err
	}
	payload, err := c.cipherRead.Open(payloadBuf[:0], c.nonceRead, payloadBuf, nil)
	if err != nil {
		pool.Put(payloadBuf)
		return protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	if len(payload) > 0 {
		c.leftToRead = payload
		c.indexToRead = 0
	} else {
		pool.Put(payloadBuf)
	}
	c.onceRead = true
	return nil
}

func validSS2022Timestamp(ts uint64) bool {
	now := time.Now().Unix()
	delta := now - int64(ts)
	if delta < 0 {
		delta = -delta
	}
	return delta <= 30
}

func (c *TCPConn) readChunkFromPool() ([]byte, error) {
	bufLen := pool.Get(2 + c.cipherConf.TagLen)
	defer pool.Put(bufLen)
	//log.Warn("len(bufLen): %v, c.nonceRead: %v", len(bufLen), c.nonceRead)
	if _, err := io.ReadFull(c.Conn, bufLen); err != nil {
		return nil, err
	}
	bLenPayload, err := c.cipherRead.Open(bufLen[:0], c.nonceRead, bufLen, nil)
	if err != nil {
		//log.Warn("read length of payload: %v: %v", protocol.ErrFailAuth, err)
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	lenPayload := binary.BigEndian.Uint16(bLenPayload)
	bufPayload := pool.Get(int(lenPayload) + c.cipherConf.TagLen) // delay putting back
	if _, err = io.ReadFull(c.Conn, bufPayload); err != nil {
		return nil, err
	}
	payload, err := c.cipherRead.Open(bufPayload[:0], c.nonceRead, bufPayload, nil)
	if err != nil {
		//log.Warn("read payload: %v: %v", protocol.ErrFailAuth, err)
		return nil, protocol.ErrFailAuth
	}
	common.BytesIncLittleEndian(c.nonceRead)
	return payload, nil
}

func (c *TCPConn) initWriteFromPool(b []byte) (buf []byte, offset int, toWrite []byte, err error) {
	var mdata = Metadata{
		Metadata: c.metadata,
	}
	var prefix, suffix []byte
	if c.metadata.Type == protocol.MetadataTypeMsg {
		mdata.LenMsgBody = uint32(len(b))
		suffix = pool.Get(CalcPaddingLen(c.masterKey, b, c.metadata.IsClient))
		defer pool.Put(suffix)
	}
	if c.metadata.IsClient || c.metadata.Type == protocol.MetadataTypeMsg {
		prefix, err = mdata.BytesFromPool()
		if err != nil {
			return nil, 0, nil, err
		}
		defer pool.Put(prefix)
	}
	toWrite = pool.Get(len(prefix) + len(b) + len(suffix))
	copy(toWrite, prefix)
	copy(toWrite[len(prefix):], b)
	copy(toWrite[len(prefix)+len(b):], suffix)

	buf = pool.Get(c.cipherConf.SaltLen + c.encryptedPayloadLen(len(toWrite)))
	salt := c.sg.Get()
	copy(buf, salt)
	pool.Put(salt)
	subKey := pool.Get(c.cipherConf.KeyLen)
	defer pool.Put(subKey)
	if err = deriveSessionSubKey(subKey, c.metadata.Cipher, c.masterKey, buf[:c.cipherConf.SaltLen], ciphers.ShadowsocksReusedInfo); err != nil {
		pool.Put(buf)
		pool.Put(toWrite)
		return nil, 0, nil, err
	}
	c.cipherWrite, err = c.cipherConf.NewCipher(subKey)
	if err != nil {
		pool.Put(buf)
		pool.Put(toWrite)
		return nil, 0, nil, err
	}
	offset += c.cipherConf.SaltLen
	if c.bloom != nil {
		c.bloom.ExistOrAdd(buf[:c.cipherConf.SaltLen])
	}
	//log.Trace("salt(%p): %v", &b, hex.EncodeToString(buf[:c.cipherConf.SaltLen]))
	return buf, offset, toWrite, nil
}

func (c *TCPConn) Write(b []byte) (n int, err error) {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	if c.is2022 {
		return c.write2022(b)
	}
	var buf []byte
	var toPack []byte
	var offset int
	if !c.onceWrite {
		c.onceWrite = true
		buf, offset, toPack, err = c.initWriteFromPool(b)
		if err != nil {
			return 0, err
		}
		defer pool.Put(toPack)
	}
	if buf == nil {
		buf = pool.Get(c.encryptedPayloadLen(len(b)))
		toPack = b
	}
	defer pool.Put(buf)
	if c.cipherWrite == nil {
		return 0, fmt.Errorf("%v: %w", ErrFailInitCipher, err)
	}
	c.seal(buf[offset:], toPack)
	//log.Trace("to write(%p): %v", &b, hex.EncodeToString(buf[:c.cipherConf.SaltLen]))
	_, err = c.Conn.Write(buf)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *TCPConn) write2022(b []byte) (int, error) {
	if !c.onceWrite {
		c.onceWrite = true
		salt := c.sg.Get()
		c.requestSalt = make([]byte, len(salt))
		copy(c.requestSalt, salt)
		subKey := pool.Get(c.cipherConf.KeyLen)
		if err := deriveSessionSubKey(subKey, c.metadata.Cipher, c.masterKey, salt, ciphers.ShadowsocksReusedInfo); err != nil {
			pool.Put(subKey)
			pool.Put(salt)
			return 0, err
		}
		cipherWrite, err := c.cipherConf.NewCipher(subKey)
		pool.Put(subKey)
		if err != nil {
			pool.Put(salt)
			return 0, fmt.Errorf("%v: %w", ErrFailInitCipher, err)
		}
		c.cipherWrite = cipherWrite
		if c.bloom != nil {
			c.bloom.ExistOrAdd(salt)
		}
		paddingLen := 0
		initialPayloadLen := 0
		if len(b) > 0 {
			initialPayloadLen = 0
		}
		if initialPayloadLen == 0 {
			paddingLen = int(fastrand.Uint32()%32) + 1
		}
		varHeader, err := c.build2022VarHeader(b[:initialPayloadLen], paddingLen)
		if err != nil {
			pool.Put(salt)
			return 0, err
		}
		if len(varHeader) > math.MaxUint16 {
			pool.Put(salt)
			return 0, fmt.Errorf("shadowsocks 2022 header too large: %d", len(varHeader))
		}
		fixedHeader := make([]byte, 1+8+2)
		fixedHeader[0] = 0
		binary.BigEndian.PutUint64(fixedHeader[1:], uint64(time.Now().Unix()))
		binary.BigEndian.PutUint16(fixedHeader[9:], uint16(len(varHeader)))
		remaining := b[initialPayloadLen:]
		totalLen := c.cipherConf.SaltLen + len(fixedHeader) + c.cipherConf.TagLen + len(varHeader) + c.cipherConf.TagLen + c.encryptedPayloadLen(len(remaining))
		buf := pool.Get(totalLen)
		offset := 0
		copy(buf[offset:], salt)
		pool.Put(salt)
		offset += c.cipherConf.SaltLen
		sealed := c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, fixedHeader, nil)
		offset += len(sealed)
		common.BytesIncLittleEndian(c.nonceWrite)
		sealed = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, varHeader, nil)
		offset += len(sealed)
		common.BytesIncLittleEndian(c.nonceWrite)
		if len(remaining) > 0 {
			sealed = c.seal(buf[offset:], remaining)
			offset += len(sealed)
		}
		_, err = c.Conn.Write(buf[:offset])
		pool.Put(buf)
		if err != nil {
			return 0, err
		}
		return len(b), nil
	}
	buf := pool.Get(c.encryptedPayloadLen(len(b)))
	defer pool.Put(buf)
	sealed := c.seal(buf, b)
	_, err := c.Conn.Write(sealed)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *TCPConn) build2022VarHeader(initialPayload []byte, paddingLen int) ([]byte, error) {
	meta := Metadata{Metadata: c.metadata}
	addrBytes, err := meta.Bytes()
	if err != nil {
		return nil, err
	}
	varHeader := make([]byte, 0, len(addrBytes)+2+paddingLen+len(initialPayload))
	varHeader = append(varHeader, addrBytes...)
	var paddingField [2]byte
	binary.BigEndian.PutUint16(paddingField[:], uint16(paddingLen))
	varHeader = append(varHeader, paddingField[:]...)
	if paddingLen > 0 {
		padding := make([]byte, paddingLen)
		fastrand.Read(padding)
		varHeader = append(varHeader, padding...)
	}
	varHeader = append(varHeader, initialPayload...)
	return varHeader, nil
}

func (c *TCPConn) seal(buf []byte, b []byte) []byte {
	offset := 0
	limit := c.chunkLimit
	for i := 0; i < len(b); i += limit {
		// write chunk
		var l = common.Min(limit, len(b)-i)
		binary.BigEndian.PutUint16(buf[offset:], uint16(l))
		_ = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, buf[offset:offset+2], nil)
		offset += 2 + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)

		_ = c.cipherWrite.Seal(buf[offset:offset], c.nonceWrite, b[i:i+l], nil)
		offset += l + c.cipherConf.TagLen
		common.BytesIncLittleEndian(c.nonceWrite)
	}
	return buf[:offset]
}

func (c *TCPConn) ReadMetadata() (metadata Metadata, err error) {
	var firstTwoBytes = pool.Get(2)
	defer pool.Put(firstTwoBytes)
	if _, err = io.ReadFull(c, firstTwoBytes); err != nil {
		return Metadata{}, err
	}
	n, err := BytesSizeForMetadata(firstTwoBytes)
	if err != nil {
		return Metadata{}, err
	}
	var bytesMetadata = pool.Get(n)
	defer pool.Put(bytesMetadata)
	copy(bytesMetadata, firstTwoBytes)
	_, err = io.ReadFull(c, bytesMetadata[2:])
	if err != nil {
		return Metadata{}, err
	}
	mdata, err := NewMetadata(bytesMetadata)
	if err != nil {
		return Metadata{}, err
	}
	metadata = *mdata
	// complete metadata
	if !c.metadata.IsClient {
		c.metadata.Type = metadata.Metadata.Type
		c.metadata.Hostname = metadata.Metadata.Hostname
		c.metadata.Port = metadata.Metadata.Port
		if metadata.Type == protocol.MetadataTypeMsg {
			c.metadata.Cmd = protocol.MetadataCmdResponse
		} else {
			c.metadata.Cmd = metadata.Metadata.Cmd
		}
	}
	return metadata, nil
}

func CalcPaddingLen(masterKey []byte, bodyWithoutAddr []byte, req bool) (length int) {
	maxPadding := common.Max(int(10*float64(len(bodyWithoutAddr))/(1+math.Log(float64(len(bodyWithoutAddr)))))-len(bodyWithoutAddr), 0)
	if maxPadding == 0 {
		return 0
	}
	var h hash.Hash32
	if req {
		h = fnv.New32a()
	} else {
		h = fnv.New32()
	}
	h.Write(masterKey)
	h.Write(bodyWithoutAddr)
	return int(h.Sum32()) % maxPadding
}
