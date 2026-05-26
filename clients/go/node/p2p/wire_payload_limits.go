package p2p

import "github.com/2tbmz9y2xt-lang/rubin-protocol/clients/go/consensus"

func inventoryPayloadCap() uint32 {
	return uint32(maxInventoryVectors * inventoryVectorSize)
}

func addrPayloadCap() uint32 {
	return uint32(maxCompactSizeBytes + maxAddrPayloadEntries*addrPayloadEntrySize)
}

func getBlocksPayloadCap(locatorLimit int) uint32 {
	if locatorLimit <= 0 {
		locatorLimit = defaultLocatorLimit
	}
	return uint32(2 + locatorLimit*32 + 32)
}

func headersPayloadCap(headerBatchLimit uint64) uint32 {
	if headerBatchLimit == 0 {
		headerBatchLimit = 512
	}
	return uint32(headerBatchLimit * consensus.BLOCK_HEADER_BYTES)
}

func compactRelayPayloadCap(command string) uint32 {
	if command == messageSendCmpct {
		return sendCmpctPayloadBytes
	}
	if command == messageGetBlockTxn {
		return uint32(32 + maxCompactSizeBytes + maxCompactRelayEntries*compactRelayIndexBytes)
	}
	if command == messageCmpctBlock {
		return uint32(consensus.MAX_RELAY_MSG_BYTES)
	}
	if command == messageBlockTxn {
		return uint32(consensus.MAX_BLOCK_BYTES + 32 + maxCompactSizeBytes + maxCompactRelayEntries*maxCompactSizeBytes)
	}
	if command == messageGetDAChunk {
		return getDAChunkPayloadCap()
	}
	return 0
}

func postHandshakePayloadCap(locatorLimit int, headerBatchLimit uint64) payloadLimitFn {
	return func(command string) uint32 {
		if cap, ok := fixedPostHandshakePayloadCap(command); ok {
			return cap
		}
		if cap := compactRelayPayloadCap(command); cap != 0 {
			return cap
		}
		return variablePostHandshakePayloadCap(command, locatorLimit, headerBatchLimit)
	}
}

func fixedPostHandshakePayloadCap(command string) (uint32, bool) {
	switch command {
	case messageVersion:
		return versionPayloadBytes, true
	case messageVerAck, messageGetAddr, messagePing, messagePong:
		return 0, true
	default:
		return 0, false
	}
}

func variablePostHandshakePayloadCap(command string, locatorLimit int, headerBatchLimit uint64) uint32 {
	switch command {
	case messageInv, messageGetData:
		return inventoryPayloadCap()
	case messageAddr:
		return addrPayloadCap()
	case messageGetBlk:
		return getBlocksPayloadCap(locatorLimit)
	case messageHeaders:
		return headersPayloadCap(headerBatchLimit)
	case messageBlock, messageTx:
		return uint32(consensus.MAX_BLOCK_BYTES)
	default:
		return 0
	}
}
