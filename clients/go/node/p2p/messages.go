package p2p

const (
	CmdVersion = "version"
	CmdVerack  = "verack"
	CmdReject  = "reject"

	CmdInv        = "inv"
	CmdGetData    = "getdata"
	CmdNotFound   = "notfound"
	CmdGetHeaders = "getheaders"
	CmdHeaders    = "headers"
	CmdBlock      = "block"
	CmdTx         = "tx"
	CmdPing       = "ping"
	CmdPong       = "pong"

	// Compact blocks (spec/RUBIN_L1_P2P_PROTOCOL_v1.1.md §5.3.1).
	CmdSendCmpct   = "sendcmpct"
	CmdCmpctBlock  = "cmpctblock"
	CmdGetBlockTxn = "getblocktxn"
	CmdBlockTxn    = "blocktxn"
)

const (
	RejectMalformed       = 0x01
	RejectInvalid         = 0x10
	RejectObsolete        = 0x11
	RejectDuplicate       = 0x12
	RejectNonstandard     = 0x40
	RejectDust            = 0x41
	RejectInsufficientFee = 0x42
	RejectCheckpoint      = 0x43
)
