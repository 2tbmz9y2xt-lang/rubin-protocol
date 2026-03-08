package p2p

func (p *peer) handleGetAddr(payload []byte) error {
	if len(payload) != 0 {
		return nil
	}
	addrs := p.service.discoverableAddrs(maxAddrAdvertise)
	encoded, err := encodeAddrPayload(addrs)
	if err != nil {
		return err
	}
	return p.send(messageAddr, encoded)
}

func (p *peer) handleAddr(payload []byte) error {
	addrs, err := decodeAddrPayload(payload)
	if err != nil {
		return err
	}
	p.service.addrMgr.AddAddrs(addrs)
	p.service.connectDiscoveredAddrs(addrs)
	return nil
}
