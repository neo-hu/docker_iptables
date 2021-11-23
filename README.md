# docker 修改iptables

```
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

```

```
go build -o its main.go
docker build -t its:0.0.1 ./
docker run --rm  --privileged=true --network host  -it its:0.0.1
docker run --rm  --cap-add NET_ADMIN --cap-add NET_RAW --network host  -it its:0.0.1
```

需要配置k8s集群设备iptables 禁用某些端口
```
kubectl apply -f daemonsets.yaml
```

