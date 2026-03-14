package consensus

import "sync"

func resetOpenSSLBootstrapStateForTests() {
	opensslBootstrapOnce = sync.Once{}
	opensslBootstrapErr = nil
	opensslConsensusInitOnce = sync.Once{}
	opensslConsensusInitErr = nil
	opensslBootstrapFn = opensslBootstrap
	opensslConsensusInitFn = opensslConsensusInit
}
