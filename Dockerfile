FROM registry.cn-hangzhou.aliyuncs.com/google_containers/kube-proxy:v1.22.0
MAINTAINER neo.ajax@qq.com
WORKDIR /
RUN echo "Asia/Shanghai" > /etc/timezone
ADD its /its
CMD ["/its"]
