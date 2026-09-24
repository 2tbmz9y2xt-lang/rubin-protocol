package consensus

func nativeSuiteMembershipError(nativeSuites *NativeSuiteSet, msg string) error {
	if nativeSuites == nil {
		return txerrWithCause(TX_ERR_SIG_ALG_INVALID, msg, TxErrorCauseNativeSuiteSetUnavailable)
	}
	return txerr(TX_ERR_SIG_ALG_INVALID, msg)
}
