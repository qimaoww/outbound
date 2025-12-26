package tls

import "github.com/qimaoww/outbound/dialer"

func init() {
	dialer.FromLinkRegister("tls", NewTls)
	dialer.FromLinkRegister("utls", NewTls)
}
