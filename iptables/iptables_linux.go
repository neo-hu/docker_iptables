// +build linux

package iptables

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

type locker struct {
	lock16 *os.File
	lock14 *net.UnixListener
}

func (l *locker) Close() error {
	var errList []error
	if l.lock16 != nil {
		if err := l.lock16.Close(); err != nil {
			errList = append(errList, err)
		}
	}
	if l.lock14 != nil {
		if err := l.lock14.Close(); err != nil {
			errList = append(errList, err)
		}
	}
	return NewAggregate(errList)
}

func grabIptablesLocks(lockfilePath14x, lockfilePath16x string) (iptablesLocker, error) {
	var err error
	var success bool

	l := &locker{}
	defer func(l *locker) {
		// Clean up immediately on failure
		if !success {
			l.Close()
		}
	}(l)

	// Grab both 1.6.x and 1.4.x-style locks; we don't know what the
	// iptables-restore version is if it doesn't support --wait, so we
	// can't assume which lock method it'll use.

	// Roughly duplicate iptables 1.6.x xtables_lock() function.
	l.lock16, err = os.OpenFile(lockfilePath16x, os.O_CREATE, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open iptables lock %s: %v", lockfilePath16x, err)
	}
	for i := 0; i < 10; i++ {
		select {
		case <- time.After(200*time.Millisecond):
			if err := grabIptablesFileLock(l.lock16); err != nil {
				continue
			}
			break
		}
	}
	// Roughly duplicate iptables 1.4.x xtables_lock() function.
	for i := 0; i < 10; i++ {
		select {
		case <- time.After(200*time.Millisecond):
			l.lock14, err = net.ListenUnix("unix", &net.UnixAddr{Name: lockfilePath14x, Net: "unix"})
			if err != nil {
				continue
			}
			break
		}
	}
	success = true
	return l, nil
}

func grabIptablesFileLock(f *os.File) error {
	return unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
