package main

import (
	"fmt"
	"github.com/neo-hu/docker_iptables/iptables"
	"strings"
)

type debugLogging struct {

}

func (d debugLogging) Printf(format string, args ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	fmt.Printf(format, args...)
}

func main() {
	iptables.SetLogging(&debugLogging{})
	iptInterface := iptables.New(iptables.ProtocolIPv4)

	// todo 禁用端口
	// iptables -w -C INPUT -t filter -p tcp -m tcp --dport 10256 -j DROP -m comment --comment internet kube-proxy 10256
	fmt.Println(iptInterface.EnsureRule(iptables.Append, iptables.TableFilter, iptables.ChainInput,
		"-p", "tcp", "-m", "tcp", "--dport", "10256",
		"-j", "DROP", "-m", "comment", "--comment", "internet kube-proxy 10256"))
}
