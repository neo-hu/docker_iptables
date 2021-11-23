package iptables

type LoggingT interface {
	Printf(format string, args ...interface{})
}
type emptyLogging struct {
}

var logging LoggingT = &emptyLogging{}

func (l *emptyLogging) Printf(format string, args ...interface{}) {

}

func SetLogging(l LoggingT)  {
	logging = l
}

func Infof(format string, args ...interface{}) {
	logging.Printf(format, args...)
}
