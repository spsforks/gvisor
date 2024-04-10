// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package fdbased

import (
	"encoding/binary"

	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/hash/jenkins"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/stack/gro"
)

type processor struct {
	mu sync.Mutex
	// +checklocks:mu
	pkts stack.PacketBufferList

	e           *endpoint
	gro         gro.GRO
	sleeper     sleep.Sleeper
	packetWaker sleep.Waker
	closeWaker  sleep.Waker
}

func (p *processor) start(wg *sync.WaitGroup) {
	defer wg.Done()
	defer p.sleeper.Done()
	for {
		switch w := p.sleeper.Fetch(true); {
		case w == &p.packetWaker:
			p.deliverPackets()
		case w == &p.closeWaker:
			p.mu.Lock()
			p.pkts.Reset()
			p.mu.Unlock()
			return
		}
	}
}

func (p *processor) deliverPackets() {
	p.e.mu.RLock()
	p.gro.Dispatcher = p.e.dispatcher
	p.e.mu.RUnlock()

	p.mu.Lock()
	for p.pkts.Len() > 0 {
		pkt := p.pkts.PopFront()
		p.mu.Unlock()
		p.gro.Enqueue(pkt)
		pkt.DecRef()
		p.mu.Lock()
	}
	p.mu.Unlock()
	p.gro.Flush()
}

// processorManager handles starting, closing, and queuing packets on processor
// goroutines.
type processorManager struct {
	processors []processor
	seed       uint32
	wg         sync.WaitGroup
	e          *endpoint
	ready      map[*processor]struct{}
}

func (m *processorManager) start(opts *Options, e *endpoint) {
	m.seed = rand.Uint32()
	m.ready = make(map[*processor]struct{})
	m.processors = make([]processor, opts.ThreadsPerChannel)
	m.e = e
	m.wg.Add(opts.ThreadsPerChannel)

	for i := range m.processors {
		p := &m.processors[i]
		p.sleeper.AddWaker(&p.packetWaker)
		p.sleeper.AddWaker(&p.closeWaker)
		p.gro.Init(opts.GRO)
		p.e = e
		// Only start processor in a separate goroutine if we have multiple of them.
		if len(m.processors) > 1 {
			go p.start(&m.wg)
		}
	}
}

func (m *processorManager) connectionHash(cid *connectionID) uint32 {
	var payload [4]byte
	binary.LittleEndian.PutUint16(payload[0:], cid.srcPort)
	binary.LittleEndian.PutUint16(payload[2:], cid.dstPort)

	h := jenkins.Sum32(m.seed)
	h.Write(payload[:])
	h.Write(cid.srcAddr)
	h.Write(cid.dstAddr)
	return h.Sum32()
}

// queuePacket queues a packet to be delivered to the appropriate processor.
func (m *processorManager) queuePacket(pkt *stack.PacketBuffer, hasEthHeader bool) {
	var p *processor
	if len(m.processors) > 1 {
		cid, nonConnectionPkt := tcpipConnectionID(pkt)
		if !hasEthHeader {
			if nonConnectionPkt {
				return
			}
			pkt.NetworkProtocolNumber = cid.proto
		}
		// If the packet is not associated with an active connection, use the
		// first processor.
		if nonConnectionPkt {
			p = &m.processors[0]
		} else {
			p = &m.processors[m.connectionHash(&cid)%uint32(len(m.processors))]
		}
	} else {
		p = &m.processors[0]
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	pkt.IncRef()
	p.pkts.PushBack(pkt)
	m.ready[p] = struct{}{}
}

type connectionID struct {
	proto            tcpip.NetworkProtocolNumber
	srcAddr, dstAddr []byte
	srcPort, dstPort uint16
}

// tcpipConnectionID returns a tcpip connection id tuple based on the data found
// in the packet. It returns true if the packet is not associated with an active
// connection (e.g ARP, NDP, etc). The method assumes link headers have already
// been processed if they were present.
func tcpipConnectionID(pkt *stack.PacketBuffer) (connectionID, bool) {
	var cid connectionID
	h, ok := pkt.Data().PullUp(1)
	if !ok {
		// Skip this packet.
		return cid, true
	}

	switch header.IPVersion(h) {
	case header.IPv4Version:
		hdrLen := header.IPv4(h).HeaderLength()
		h, ok = pkt.Data().PullUp(int(hdrLen) + 4)
		if !ok {
			panic("failed to pull up header")
		}
		ipHdr := header.IPv4(h[:hdrLen])
		tcpHdr := header.TCP(h[hdrLen : hdrLen+header.TCPMinimumSize])

		cid.srcAddr = ipHdr.SourceAddressSlice()
		cid.dstAddr = ipHdr.DestinationAddressSlice()
		cid.srcPort = tcpHdr.SourcePort()
		cid.dstPort = tcpHdr.DestinationPort()
		cid.proto = header.IPv4ProtocolNumber
	case header.IPv6Version:
		h, ok = pkt.Data().PullUp(header.IPv6FixedHeaderSize + 4)
		if !ok {
			panic("failed to pull up header")
		}
		ipHdr := header.IPv6(h[:header.IPv6FixedHeaderSize])
		if tcpip.TransportProtocolNumber(ipHdr.NextHeader()) != header.TCPProtocolNumber {
			return cid, true
		}
		tcpHdr := header.TCP(h[header.IPv6FixedHeaderSize : header.IPv6FixedHeaderSize+header.TCPMinimumSize])
		cid.srcAddr = ipHdr.SourceAddressSlice()
		cid.dstAddr = ipHdr.DestinationAddressSlice()
		cid.srcPort = tcpHdr.SourcePort()
		cid.dstPort = tcpHdr.DestinationPort()
		cid.proto = header.IPv6ProtocolNumber
	default:
		return cid, true
	}
	return cid, false
}

func (m *processorManager) close() {
	if len(m.processors) < 2 {
		return
	}
	for i := range m.processors {
		p := &m.processors[i]
		p.closeWaker.Assert()
	}
}

// wakeReady wakes up all processors that have a packet queued. If there is only
// a single active connection, the method delivers the packet inline without
// waking a goroutine.
func (m *processorManager) wakeReady() {
	for p := range m.ready {
		if len(m.processors) > 1 {
			p.packetWaker.Assert()
		} else {
			p.deliverPackets()
		}
		delete(m.ready, p)
	}
}
