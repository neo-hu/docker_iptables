# docker 修改iptables


```
go build -o its main.go
docker build -t its:0.0.1 ./
docker run --rm  --privileged=true --network host  -it its:0.0.1
docker run --rm  --cap-add NET_ADMIN --cap-add NET_RAW --network host  -it its:0.0.1
```

需要配置k8s集群设备iptables 禁用某些端口

