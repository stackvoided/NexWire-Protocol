package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/curve25519"
)

type ClientPeer struct {
	Addr       *net.UDPAddr
	Session    *SessionCipher
	SessionID  uint32
	LastActive int64
}

type Server struct {
	cfg       *Config
	tun       *TUN
	conn      *net.UDPConn
	peers     sync.Map
	ipToPeer  sync.Map
	pool      sync.Pool
	ctx       context.Context
	cancel    context.CancelFunc
	globalSeq uint64
	staticKP  *KeyPair
}

func NewServer(cfg *Config) (*Server, error) {
	tun, err := NewTUN(cfg.TunName, cfg.TunIP, cfg.MTU)
	if err != nil {
		return nil, err
	}

	addr, err := net.ResolveUDPAddr("udp", cfg.ListenAddr)
	if err != nil {
		tun.Close()
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		tun.Close()
		return nil, err
	}

	_ = conn.SetReadBuffer(4194304)
	_ = conn.SetWriteBuffer(4194304)

	kp, err := GenerateKeyPair()
	if err != nil {
		tun.Close()
		conn.Close()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		cfg:      cfg,
		tun:      tun,
		conn:     conn,
		staticKP: kp,
		ctx:      ctx,
		cancel:   cancel,
		pool: sync.Pool{
			New: func() any {
				b := make([]byte, 65535)
				return &b
			},
		},
	}, nil
}

func (s *Server) Start() {
	log.Printf("[SERVER] Started on %s [TUN: %s]", s.cfg.ListenAddr, s.tun.Name())

	go s.tunReadLoop()

	for i := 0; i < s.cfg.Workers; i++ {
		go s.udpWorkerLoop()
	}

	go s.reaperLoop()

	<-s.ctx.Done()
	s.Shutdown()
}

func (s *Server) udpWorkerLoop() {
	bufPtr := s.pool.Get().(*[]byte)
	buf := *bufPtr
	defer s.pool.Put(bufPtr)

	outPtr := s.pool.Get().(*[]byte)
	outBuf := *outPtr
	defer s.pool.Put(outPtr)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, raddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		if n < HeaderSize {
			continue
		}

		header, err := DecodeHeader(buf[:HeaderSize])
		if err != nil {
			continue
		}

		payload := buf[HeaderSize:n]

		switch header.Type {
		case MsgTypeHandshakeInit:
			s.handleHandshake(payload, raddr)

		case MsgTypeData:
			peerVal, ok := s.peers.Load(header.SessionID)
			if !ok {
				continue
			}
			peer := peerVal.(*ClientPeer)

			decrypted, err := peer.Session.Decrypt(outBuf[:0], payload, header.Sequence)
			if err != nil {
				continue
			}

			atomic.StoreInt64(&peer.LastActive, time.Now().Unix())

			if srcIP, _, ok := ExtractIPs(decrypted); ok {
				s.ipToPeer.Store(srcIP.String(), peer)
			}

			_, _ = s.tun.Write(decrypted)

		case MsgTypeKeepalive:
			if peerVal, ok := s.peers.Load(header.SessionID); ok {
				atomic.StoreInt64(&peerVal.(*ClientPeer).LastActive, time.Now().Unix())
			}
		}
	}
}

func (s *Server) handleHandshake(payload []byte, raddr *net.UDPAddr) {
	hs, err := UnmarshalHandshake(payload)
	if err != nil {
		return
	}

	mac := hmac.New(sha256.New, []byte(s.cfg.PSK))
	mac.Write(hs.EphPublicKey[:])
	tsBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(tsBuf, uint64(hs.Timestamp))
	mac.Write(tsBuf)

	if !hmac.Equal(hs.HMAC[:], mac.Sum(nil)) {
		return
	}

	var sharedSecret [32]byte
	curve25519.ScalarMult(&sharedSecret, &s.staticKP.Private, &hs.EphPublicKey)

	session, err := NewSessionCipher(sharedSecret[:])
	if err != nil {
		return
	}

	sessionID := binary.BigEndian.Uint32(hs.EphPublicKey[0:4])
	peer := &ClientPeer{
		Addr:       raddr,
		Session:    session,
		SessionID:  sessionID,
		LastActive: time.Now().Unix(),
	}

	s.peers.Store(sessionID, peer)

	serverEph, _ := GenerateKeyPair()
	var respHMAC [32]byte
	respMac := hmac.New(sha256.New, []byte(s.cfg.PSK))
	respMac.Write(serverEph.Public[:])
	copy(respHMAC[:], respMac.Sum(nil))

	respHs := HandshakeMessage{
		EphPublicKey: serverEph.Public,
		Timestamp:    time.Now().Unix(),
		HMAC:         respHMAC,
	}

	respData := MarshalHandshake(respHs)
	hdr := make([]byte, HeaderSize)
	EncodeHeader(PacketHeader{Type: MsgTypeHandshakeResp, Sequence: 0, SessionID: sessionID}, hdr)

	_, _ = s.conn.WriteToUDP(append(hdr, respData...), raddr)
}

func (s *Server) tunReadLoop() {
	bufPtr := s.pool.Get().(*[]byte)
	buf := *bufPtr
	defer s.pool.Put(bufPtr)

	outPtr := s.pool.Get().(*[]byte)
	outBuf := *outPtr
	defer s.pool.Put(outPtr)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, err := s.tun.Read(buf)
		if err != nil {
			continue
		}

		packet := buf[:n]
		_, dstIP, ok := ExtractIPs(packet)
		if !ok {
			continue
		}

		peerVal, ok := s.ipToPeer.Load(dstIP.String())
		if !ok {
			continue
		}
		peer := peerVal.(*ClientPeer)

		seq := atomic.AddUint64(&s.globalSeq, 1)

		EncodeHeader(PacketHeader{
			Type:      MsgTypeData,
			Sequence:  seq,
			SessionID: peer.SessionID,
		}, outBuf[:HeaderSize])

		encrypted, err := peer.Session.Encrypt(outBuf[HeaderSize:HeaderSize], packet, seq)
		if err != nil {
			continue
		}

		_, _ = s.conn.WriteToUDP(outBuf[:HeaderSize+len(encrypted)], peer.Addr)
	}
}

func (s *Server) reaperLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now().Unix()
			s.peers.Range(func(key, value any) bool {
				peer := value.(*ClientPeer)
				if now-atomic.LoadInt64(&peer.LastActive) > 120 {
					s.peers.Delete(key)
				}
				return true
			})
		}
	}
}

func (s *Server) Shutdown() {
	s.cancel()
	_ = s.conn.Close()
	_ = s.tun.Close()
	log.Println("[SERVER] Gracefully stopped.")
}
