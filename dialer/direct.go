package dialer

import (
	"github.com/qimaoww/outbound/netproxy"
	softwindDirect "github.com/qimaoww/outbound/protocol/direct"
)

func NewDirectDialer(option *ExtraOption, fullcone bool) (netproxy.Dialer, *Property) {
	property := &Property{
		Name:     "direct",
		Address:  "",
		Protocol: "",
		Link:     "",
	}
	if fullcone {
		return softwindDirect.FullconeDirect, property
	} else {
		return softwindDirect.SymmetricDirect, property
	}
}
