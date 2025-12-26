package simpleobfs

import "github.com/qimaoww/outbound/dialer"

func init() {
	dialer.FromLinkRegister("simpleobfs", NewSimpleObfs)
}
