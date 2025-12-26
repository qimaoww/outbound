package shadowsocks

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	disk_bloom "github.com/mzz2017/disk-bloom"
	"github.com/qimaoww/outbound/ciphers"
	"github.com/qimaoww/outbound/netproxy"
	"github.com/qimaoww/outbound/pkg/fastrand"
	"github.com/qimaoww/outbound/pool"
	"github.com/qimaoww/outbound/protocol"
	"golang.org/x/crypto/chacha20poly1305"
	"lukechampine.com/blake3"
)

type UdpConn struct {
	netproxy.PacketConn

	proxyAddress string

	metadata        protocol.Metadata
	cipherConf      *ciphers.CipherConf
	masterKey       []byte
	bloom           *disk_bloom.FilterGroup
	sg              SaltGenerator
	is2022          bool
	is2022Chacha    bool
	clientSessionID [8]byte
	packetID        uint64
	block           cipher.Block
	aeadX           cipher.AEAD

	tgtAddr string
}

func NewUdpConn(conn netproxy.PacketConn, proxyAddress string, metadata protocol.Metadata, masterKey []byte, bloom *disk_bloom.FilterGroup) (*UdpConn, error) {
	conf := ciphers.AeadCiphersConf[metadata.Cipher]
	if conf.NewCipher == nil {
		return nil, fmt.Errorf("invalid CipherConf")
	}
	key := make([]byte, len(masterKey))
	copy(key, masterKey)
	is2022 := isShadowsocks2022(metadata.Cipher)
	isChacha := strings.Contains(metadata.Cipher, "chacha20")
	var sg SaltGenerator
	var err error
	if !is2022 {
		sg, err = GetSaltGenerator(masterKey, conf.SaltLen)
		if err != nil {
			return nil, err
		}
	}
	var blk cipher.Block
	var aeadX cipher.AEAD
	var clientSessionID [8]byte
	if is2022 {
		if isChacha {
			aeadX, err = chacha20poly1305.NewX(key)
			if err != nil {
				return nil, err
			}
		} else {
			blk, err = aes.NewCipher(key)
			if err != nil {
				return nil, err
			}
		}
		fastrand.Read(clientSessionID[:])
	}
	c := &UdpConn{
		PacketConn:      conn,
		proxyAddress:    proxyAddress,
		metadata:        metadata,
		cipherConf:      conf,
		masterKey:       key,
		bloom:           bloom,
		sg:              sg,
		is2022:          is2022,
		is2022Chacha:    isChacha,
		clientSessionID: clientSessionID,
		block:           blk,
		aeadX:           aeadX,
		tgtAddr:         net.JoinHostPort(metadata.Hostname, strconv.Itoa(int(metadata.Port))),
	}
	return c, nil
}

func (c *UdpConn) Close() error {
	return c.PacketConn.Close()
}

func (c *UdpConn) Read(b []byte) (n int, err error) {
	n, _, err = c.ReadFrom(b)
	return
}

func (c *UdpConn) Write(b []byte) (n int, err error) {
	if err != nil {
		return 0, err
	}
	return c.WriteTo(b, c.tgtAddr)
}

func (c *UdpConn) WriteTo(b []byte, addr string) (int, error) {
	if c.is2022 {
		return c.writeTo2022(b, addr)
	}
	metadata := Metadata{
		Metadata: c.metadata,
	}
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	metadata.Hostname = mdata.Hostname
	metadata.Port = mdata.Port
	metadata.Type = mdata.Type
	prefix, err := metadata.BytesFromPool()
	if err != nil {
		return 0, err
	}
	defer pool.Put(prefix)
	chunk := pool.Get(len(prefix) + len(b))
	defer pool.Put(chunk)
	copy(chunk, prefix)
	copy(chunk[len(prefix):], b)
	salt := c.sg.Get()
	toWrite, err := EncryptUDPFromPool(&Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
		Method:     c.metadata.Cipher,
	}, chunk, salt, ciphers.ShadowsocksReusedInfo)
	pool.Put(salt)
	if err != nil {
		return 0, err
	}
	defer pool.Put(toWrite)
	if c.bloom != nil {
		c.bloom.ExistOrAdd(toWrite[:c.cipherConf.SaltLen])
	}
	return c.PacketConn.WriteTo(toWrite, c.proxyAddress)
}

func (c *UdpConn) ReadFrom(b []byte) (n int, addr netip.AddrPort, err error) {
	if c.is2022 {
		return c.readFrom2022(b)
	}
	enc := pool.Get(len(b) + c.cipherConf.SaltLen)
	defer pool.Put(enc)
	n, addr, err = c.PacketConn.ReadFrom(enc)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	n, err = DecryptUDP(b, &Key{
		CipherConf: c.cipherConf,
		MasterKey:  c.masterKey,
		Method:     c.metadata.Cipher,
	}, enc[:n], ciphers.ShadowsocksReusedInfo)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}

	if c.bloom != nil {
		if exist := c.bloom.ExistOrAdd(enc[:c.cipherConf.SaltLen]); exist {
			err = protocol.ErrReplayAttack
			return
		}
	}
	// parse sAddr from metadata
	sizeMetadata, err := BytesSizeForMetadata(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	mdata, err := NewMetadata(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	var typ protocol.MetadataType
	switch typ {
	case protocol.MetadataTypeIPv4, protocol.MetadataTypeIPv6:
		ip, err := netip.ParseAddr(mdata.Hostname)
		if err != nil {
			return 0, netip.AddrPort{}, err
		}
		addr = netip.AddrPortFrom(ip, mdata.Port)
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("bad metadata type: %v; should be ip", typ)
	}
	copy(b, b[sizeMetadata:])
	n -= sizeMetadata
	return n, addr, nil
}

func (c *UdpConn) writeTo2022(b []byte, addr string) (int, error) {
	if c.is2022Chacha {
		return c.writeTo2022Chacha(b, addr)
	}
	return c.writeTo2022Aes(b, addr)
}

func (c *UdpConn) writeTo2022Aes(b []byte, addr string) (int, error) {
	metadata := Metadata{Metadata: c.metadata}
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	metadata.Hostname = mdata.Hostname
	metadata.Port = mdata.Port
	metadata.Type = mdata.Type
	addrBytes, err := metadata.Bytes()
	if err != nil {
		return 0, err
	}
	bodyHeader := make([]byte, 0, 1+8+2+len(addrBytes))
	bodyHeader = append(bodyHeader, 0)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
	bodyHeader = append(bodyHeader, ts[:]...)
	bodyHeader = append(bodyHeader, 0, 0) // padding length zero
	bodyHeader = append(bodyHeader, addrBytes...)
	bodyPlain := append(bodyHeader, b...)
	var sepHeader [16]byte
	copy(sepHeader[:8], c.clientSessionID[:])
	binary.BigEndian.PutUint64(sepHeader[8:], c.packetID)
	c.packetID++
	subKey := pool.Get(c.cipherConf.KeyLen)
	deriveSS2022UDPSubKey(subKey, c.masterKey, sepHeader[:8])
	aead, err := c.cipherConf.NewCipher(subKey)
	pool.Put(subKey)
	if err != nil {
		return 0, err
	}
	packet := pool.Get(16 + len(bodyPlain) + c.cipherConf.TagLen)
	copy(packet[:16], sepHeader[:])
	if c.block != nil {
		c.block.Encrypt(packet[:16], packet[:16])
	}
	nonce := sepHeader[4:16]
	ciphertext := aead.Seal(packet[16:16], nonce, bodyPlain, nil)
	packetLen := 16 + len(ciphertext)
	written, err := c.PacketConn.WriteTo(packet[:packetLen], c.proxyAddress)
	pool.Put(packet)
	return written, err
}

func (c *UdpConn) writeTo2022Chacha(b []byte, addr string) (int, error) {
	if c.aeadX == nil {
		return 0, fmt.Errorf("chacha20-2022 AEAD is not initialized")
	}
	metadata := Metadata{Metadata: c.metadata}
	mdata, err := protocol.ParseMetadata(addr)
	if err != nil {
		return 0, err
	}
	metadata.Hostname = mdata.Hostname
	metadata.Port = mdata.Port
	metadata.Type = mdata.Type
	addrBytes, err := metadata.Bytes()
	if err != nil {
		return 0, err
	}
	head := make([]byte, 0, 8+8+1+8+2+len(addrBytes))
	head = append(head, c.clientSessionID[:]...)
	var pid [8]byte
	binary.BigEndian.PutUint64(pid[:], c.packetID)
	c.packetID++
	head = append(head, pid[:]...)
	head = append(head, 0)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
	head = append(head, ts[:]...)
	head = append(head, 0, 0) // padding len
	head = append(head, addrBytes...)
	body := append(head, b...)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	fastrand.Read(nonce)
	packet := pool.Get(len(nonce) + len(body) + c.cipherConf.TagLen)
	copy(packet, nonce)
	ciphertext := c.aeadX.Seal(packet[len(nonce):len(nonce)], nonce, body, nil)
	packetLen := len(nonce) + len(ciphertext)
	written, err := c.PacketConn.WriteTo(packet[:packetLen], c.proxyAddress)
	pool.Put(packet)
	return written, err
}

func (c *UdpConn) readFrom2022(b []byte) (int, netip.AddrPort, error) {
	if c.is2022Chacha {
		return c.readFrom2022Chacha(b)
	}
	return c.readFrom2022Aes(b)
}

func (c *UdpConn) readFrom2022Aes(b []byte) (int, netip.AddrPort, error) {
	buf := pool.Get(len(b) + c.cipherConf.TagLen + 32)
	defer pool.Put(buf)
	n, _, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < 16+c.cipherConf.TagLen {
		return 0, netip.AddrPort{}, fmt.Errorf("short ss2022 udp packet")
	}
	var sepHeader [16]byte
	if c.block == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("ss2022 aes block is not initialized")
	}
	c.block.Decrypt(sepHeader[:], buf[:16])
	subKey := pool.Get(c.cipherConf.KeyLen)
	deriveSS2022UDPSubKey(subKey, c.masterKey, sepHeader[:8])
	aead, err := c.cipherConf.NewCipher(subKey)
	pool.Put(subKey)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	nonce := sepHeader[4:16]
	bodyCipher := buf[16:n]
	bodyPlain, err := aead.Open(bodyCipher[:0], nonce, bodyCipher, nil)
	if err != nil {
		return 0, netip.AddrPort{}, protocol.ErrFailAuth
	}
	if len(bodyPlain) < 1+8+8+2 {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid ss2022 udp header")
	}
	offset := 0
	typ := bodyPlain[offset]
	offset++
	ts := binary.BigEndian.Uint64(bodyPlain[offset:])
	offset += 8
	if typ != 1 || !validSS2022Timestamp(ts) {
		return 0, netip.AddrPort{}, protocol.ErrFailAuth
	}
	clientID := bodyPlain[offset : offset+8]
	offset += 8
	if !bytes.Equal(clientID, c.clientSessionID[:]) {
		return 0, netip.AddrPort{}, protocol.ErrFailAuth
	}
	padLen := int(binary.BigEndian.Uint16(bodyPlain[offset:]))
	offset += 2
	if offset+padLen > len(bodyPlain) {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid padding length")
	}
	offset += padLen
	if offset >= len(bodyPlain) {
		return 0, netip.AddrPort{}, fmt.Errorf("missing address")
	}
	metaSize, err := BytesSizeForMetadata(bodyPlain[offset:])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if offset+metaSize > len(bodyPlain) {
		return 0, netip.AddrPort{}, fmt.Errorf("metadata truncated")
	}
	mdata, err := NewMetadata(bodyPlain[offset : offset+metaSize])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload := bodyPlain[offset+metaSize:]
	addrPort, err := mdata.AddrPort()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	n = copy(b, payload)
	return n, addrPort, nil
}

func (c *UdpConn) readFrom2022Chacha(b []byte) (int, netip.AddrPort, error) {
	if c.aeadX == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("chacha20-2022 AEAD is not initialized")
	}
	buf := pool.Get(len(b) + c.cipherConf.TagLen + chacha20poly1305.NonceSizeX + 32)
	defer pool.Put(buf)
	n, _, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if n < chacha20poly1305.NonceSizeX+c.cipherConf.TagLen {
		return 0, netip.AddrPort{}, fmt.Errorf("short ss2022 chacha udp packet")
	}
	nonce := buf[:chacha20poly1305.NonceSizeX]
	bodyCipher := buf[chacha20poly1305.NonceSizeX:n]
	bodyPlain, err := c.aeadX.Open(bodyCipher[:0], nonce, bodyCipher, nil)
	if err != nil {
		return 0, netip.AddrPort{}, protocol.ErrFailAuth
	}
	if len(bodyPlain) < 8+8+1+8+8+2 {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid ss2022 chacha udp header")
	}
	offset := 0
	offset += 8 // server session id
	offset += 8 // server packet id
	typ := bodyPlain[offset]
	offset++
	ts := binary.BigEndian.Uint64(bodyPlain[offset:])
	offset += 8
	if typ != 1 || !validSS2022Timestamp(ts) {
		return 0, netip.AddrPort{}, protocol.ErrFailAuth
	}
	clientID := bodyPlain[offset : offset+8]
	offset += 8
	if !bytes.Equal(clientID, c.clientSessionID[:]) {
		return 0, netip.AddrPort{}, protocol.ErrFailAuth
	}
	padLen := int(binary.BigEndian.Uint16(bodyPlain[offset:]))
	offset += 2
	if offset+padLen > len(bodyPlain) {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid padding length")
	}
	offset += padLen
	metaSize, err := BytesSizeForMetadata(bodyPlain[offset:])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if offset+metaSize > len(bodyPlain) {
		return 0, netip.AddrPort{}, fmt.Errorf("metadata truncated")
	}
	mdata, err := NewMetadata(bodyPlain[offset : offset+metaSize])
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	payload := bodyPlain[offset+metaSize:]
	addrPort, err := mdata.AddrPort()
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	n = copy(b, payload)
	return n, addrPort, nil
}

func deriveSS2022UDPSubKey(dst []byte, masterKey []byte, sessionID []byte) {
	material := pool.Get(len(masterKey) + len(sessionID))
	copy(material, masterKey)
	copy(material[len(masterKey):], sessionID)
	blake3.DeriveKey(dst, ss2022Context, material)
	pool.Put(material)
}
