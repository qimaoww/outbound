package ws

import (
	"github.com/qimaoww/outbound/dialer"
)

func init() {
	dialer.FromLinkRegister("ws", NewWs)
	dialer.FromLinkRegister("wss", NewWs)
}
