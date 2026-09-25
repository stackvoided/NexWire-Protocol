package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log"
        "fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
)

type Client struct {
	cfg        *Config
	tun        *TUN
	conn       *net.UDPConn
	remoteAddr *net.UDPAddr
	session    *SessionCipher
	sessionID  uint32
	pool       sync.Pool
	ctx        context.Context
	cancel     context.CancelFunc
	seq        uint64
	status     int32
}

func NewClient(cfg *Config) (*Client, error) {
	tun, err := NewTUN(cfg.TunName, cfg.TunIP, cfg.MTU)
	if err != nil {
		return nil, err
	}

	raddr, err := net.ResolveUDPAddr("udp", cfg.RemoteAddr)
	if err != nil {
		tun.Close()
		return nil, err
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		tun.Close()
		return nil, err
	}

	_ = conn.SetReadBuffer(4194304)
	_ = conn.SetWriteBuffer(4194304)

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		cfg:        cfg,
		tun:        tun,
		conn:       conn,
		remoteAddr: raddr,
		ctx:        ctx,
		cancel:     cancel,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, 65535)
				return &b
			},
		},
	}, nil
}

func (c *Client) Start() {
	log.Printf("[CLIENT] Initializing tunnel to %s...", c.cfg.RemoteAddr)

	if err := c.performHandshake(); err != nil {
		log.Fatalf("[CLIENT] Handshake failed: %v", err)
	}

	atomic.StoreInt32(&c.status, 1)
	log.Println("[CLIENT] Tunnel established successfully!")

	go c.tunReadLoop()
	go c.keepaliveLoop()

	for i := 0; i < c.cfg.Workers; i++ {
		go c.udpWorkerLoop()
	}

	<-c.ctx.Done()
	c.Shutdown()
}

func (c *Client) performHandshake() error {
	ephKP, err := GenerateKeyPair()
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	mac := hmac.New(sha256.New, []byte(c.cfg.PSK))
	mac.Write(ephKP.Public[:])
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(now))
	mac.Write(tsBuf)

	var hmacVal [32]byte
	copy(hmacVal[:], mac.Sum(nil))

	hsMsg := HandshakeMessage{
		EphPublicKey: ephKP.Public,
		Timestamp:    now,
		HMAC:         hmacVal,
	}

	hdr := make([]byte, HeaderSize)
	EncodeHeader(PacketHeader{Type: MsgTypeHandshakeInit, Sequence: 0, SessionID: 0}, hdr)

	payload := MarshalHandshake(hsMsg)
	packet := append(hdr, payload...)

	if _, err := c.conn.Write(packet); err != nil {
		return err
	}

	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	buf := make([]byte, 1024)
	n, err := c.conn.Read(buf)
	if err != nil {
		return fmt.Errorf("handshake response timeout: %w", err)
	}

	if n < HeaderSize+72 {
		return errors.New("invalid handshake response length")
	}

	respHdr, err := DecodeHeader(buf[:HeaderSize])
	if err != nil || respHdr.Type != MsgTypeHandshakeResp {
		return errors.New("invalid handshake response header")
	}

	respHs, err := UnmarshalHandshake(buf[HeaderSize:n])
	if err != nil {
		return err
	}

	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &ephKP.Private, &respHs.EphPublicKey)

	session, err := NewSessionCipher(sharedSecret[:])
	if err != nil {
		return err
	}

	c.session = session
	c.sessionID = respHdr.SessionID

	return nil
}

func (c *Client) tunReadLoop() {
	bufPtr := c.pool.Get().(*[]byte)
	buf := *bufPtr
	defer c.pool.Put(bufPtr)

	outPtr := sPoolGet(&c.pool)
	outBuf := *outPtr
	defer c.pool.Put(outPtr)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, err := c.tun.Read(buf)
		if err != nil {
			continue
		}

		if atomic.LoadInt32(&c.status) == 0 {
			continue
		}

		seq := atomic.AddUint64(&c.seq, 1)

		EncodeHeader(PacketHeader{
			Type:      MsgTypeData,
			Sequence:  seq,
			SessionID: c.sessionID,
		}, outBuf[:HeaderSize])

		encrypted, err := c.session.Encrypt(outBuf[HeaderSize:HeaderSize], buf[:n], seq)
		if err != nil {
			continue
		}

		_, _ = c.conn.Write(outBuf[:HeaderSize+len(encrypted)])
	}
}

func (c *Client) udpWorkerLoop() {
	bufPtr := c.pool.Get().(*[]byte)
	buf := *bufPtr
	defer c.pool.Put(bufPtr)

	outPtr := sPoolGet(&c.pool)
	outBuf := *outPtr
	defer c.pool.Put(outPtr)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, err := c.conn.Read(buf)
		if err != nil {
			continue
		}

		if n < HeaderSize {
			continue
		}

		header, err := DecodeHeader(buf[:HeaderSize])
		if err != nil || header.Type != MsgTypeData {
			continue
		}

		decrypted, err := c.session.Decrypt(outBuf[:0], buf[HeaderSize:n], header.Sequence)
		if err != nil {
			continue
		}

		_, _ = c.tun.Write(decrypted)
	}
}

func (c *Client) keepaliveLoop() {
	ticker := time.NewTicker(c.cfg.KeepaliveSec * time.Second)
	defer ticker.Stop()

	hdr := make([]byte, HeaderSize)

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			if atomic.LoadInt32(&c.status) == 1 {
				seq := atomic.AddUint64(&c.seq, 1)
				EncodeHeader(PacketHeader{Type: MsgTypeKeepalive, Sequence: seq, SessionID: c.sessionID}, hdr)
				_, _ = c.conn.Write(hdr)
			}
		}
	}
}

func (c *Client) Shutdown() {
	c.cancel()
	_ = c.conn.Close()
	_ = c.tun.Close()
	log.Println("[CLIENT] Gracefully stopped.")
}

func sPoolGet(p *sync.Pool) *[]byte {
	return p.Get().(*[]byte)
}
