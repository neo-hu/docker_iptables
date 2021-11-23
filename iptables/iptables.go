/*
来源 k8s.io
 */

package iptables

import (
	"bytes"
	"context"
	"fmt"
	"github.com/neo-hu/docker_iptables/iptables/pkg"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// RulePosition holds the -I/-A flags for iptable
type RulePosition string

const (
	// Prepend is the insert flag for iptable
	Prepend RulePosition = "-I"
	// Append is the append flag for iptable
	Append RulePosition = "-A"
)

// Interface is an injectable interface for running iptables commands.  Implementations must be goroutine-safe.
type Interface interface {
	// EnsureChain checks if the specified chain exists and, if not, creates it.  If the chain existed, return true.
	EnsureChain(table Table, chain Chain) (bool, error)
	// FlushChain clears the specified chain.  If the chain did not exist, return error.
	FlushChain(table Table, chain Chain) error
	// DeleteChain deletes the specified chain.  If the chain did not exist, return error.
	DeleteChain(table Table, chain Chain) error
	// ChainExists tests whether the specified chain exists, returning an error if it
	// does not, or if it is unable to check.
	ChainExists(table Table, chain Chain) (bool, error)
	CheckRule(table Table, chain Chain, args ...string) (bool, error)
	// EnsureRule checks if the specified rule is present and, if not, creates it.  If the rule existed, return true.
	EnsureRule(position RulePosition, table Table, chain Chain, args ...string) (bool, error)
	// DeleteRule checks if the specified rule is present and, if so, deletes it.
	DeleteRule(table Table, chain Chain, args ...string) error
	// IsIPv6 returns true if this is managing ipv6 tables.
	IsIPv6() bool
	// Protocol returns the IP family this instance is managing,
	Protocol() Protocol
	// SaveInto calls `iptables-save` for table and stores result in a given buffer.
	SaveInto(table Table, buffer *bytes.Buffer) error
	// Restore runs `iptables-restore` passing data through []byte.
	// table is the Table to restore
	// data should be formatted like the output of SaveInto()
	// flush sets the presence of the "--noflush" flag. see: FlushFlag
	// counters sets the "--counters" flag. see: RestoreCountersFlag
	Restore(table Table, data []byte, flush FlushFlag, counters RestoreCountersFlag) error
	// RestoreAll is the same as Restore except that no table is specified.
	RestoreAll(data []byte, flush FlushFlag, counters RestoreCountersFlag) error

	// HasRandomFully reveals whether `-j MASQUERADE` takes the
	// `--random-fully` option.  This is helpful to work around a
	// Linux kernel bug that sometimes causes multiple flows to get
	// mapped to the same IP:PORT and consequently some suffer packet
	// drops.
	HasRandomFully() bool
}

// Protocol defines the ip protocol either ipv4 or ipv6
type Protocol string

const (
	// ProtocolIPv4 represents ipv4 protocol in iptables
	ProtocolIPv4 Protocol = "IPv4"
	// ProtocolIPv6 represents ipv6 protocol in iptables
	ProtocolIPv6 Protocol = "IPv6"
)

// Table represents different iptable like filter,nat, mangle and raw
type Table string

const (
	// TableNAT represents the built-in nat table
	TableNAT Table = "nat"
	// TableFilter represents the built-in filter table
	TableFilter Table = "filter"
	// TableMangle represents the built-in mangle table
	TableMangle Table = "mangle"
)

// Chain represents the different rules
type Chain string

const (
	// ChainPostrouting used for source NAT in nat table
	ChainPostrouting Chain = "POSTROUTING"
	// ChainPrerouting used for DNAT (destination NAT) in nat table
	ChainPrerouting Chain = "PREROUTING"
	// ChainOutput used for the packets going out from local
	ChainOutput Chain = "OUTPUT"
	// ChainInput used for incoming packets
	ChainInput Chain = "INPUT"
	// ChainForward used for the packets for another NIC
	ChainForward Chain = "FORWARD"
)

const (
	cmdIPTablesSave     string = "iptables-save"
	cmdIPTablesRestore  string = "iptables-restore"
	cmdIPTables         string = "iptables"
	cmdIP6TablesRestore string = "ip6tables-restore"
	cmdIP6TablesSave    string = "ip6tables-save"
	cmdIP6Tables        string = "ip6tables"
)

// RestoreCountersFlag is an option flag for Restore
type RestoreCountersFlag bool

// RestoreCounters a boolean true constant for the option flag RestoreCountersFlag
const RestoreCounters RestoreCountersFlag = true

// NoRestoreCounters a boolean false constant for the option flag RestoreCountersFlag
const NoRestoreCounters RestoreCountersFlag = false

// FlushFlag an option flag for Flush
type FlushFlag bool

// FlushTables a boolean true constant for option flag FlushFlag
const FlushTables FlushFlag = true

// NoFlushTables a boolean false constant for option flag FlushFlag
const NoFlushTables FlushFlag = false

// MinCheckVersion minimum version to be checked
// Versions of iptables less than this do not support the -C / --check flag
// (test whether a rule exists).
var MinCheckVersion = pkg.MustParseGeneric("1.4.11")

// RandomFullyMinVersion is the minimum version from which the --random-fully flag is supported,
// used for port mapping to be fully randomized
var RandomFullyMinVersion = pkg.MustParseGeneric("1.6.2")

// WaitMinVersion a minimum iptables versions supporting the -w and -w<seconds> flags
var WaitMinVersion = pkg.MustParseGeneric("1.4.20")

// WaitIntervalMinVersion a minimum iptables versions supporting the wait interval useconds
var WaitIntervalMinVersion = pkg.MustParseGeneric("1.6.1")

// WaitSecondsMinVersion a minimum iptables versions supporting the wait seconds
var WaitSecondsMinVersion = pkg.MustParseGeneric("1.4.22")

// WaitRestoreMinVersion a minimum iptables versions supporting the wait restore seconds
var WaitRestoreMinVersion = pkg.MustParseGeneric("1.6.2")

// WaitString a constant for specifying the wait flag
const WaitString = "-w"

// WaitSecondsValue a constant for specifying the default wait seconds
const WaitSecondsValue = "5"

// WaitIntervalString a constant for specifying the wait interval flag
const WaitIntervalString = "-W"

// WaitIntervalUsecondsValue a constant for specifying the default wait interval useconds
const WaitIntervalUsecondsValue = "100000"

// LockfilePath16x is the iptables 1.6.x lock file acquired by any process that's making any change in the iptable rule
const LockfilePath16x = "/run/xtables.lock"

// LockfilePath14x is the iptables 1.4.x lock file acquired by any process that's making any change in the iptable rule
const LockfilePath14x = "@xtables"

// runner implements Interface in terms of exec("iptables").
type runner struct {
	mu              sync.Mutex
	protocol        Protocol
	hasCheck        bool
	hasRandomFully  bool
	waitFlag        []string
	restoreWaitFlag []string
	lockfilePath14x string
	lockfilePath16x string
}

// newInternal returns a new Interface which will exec iptables, and allows the
// caller to change the iptables-restore lockfile path
func newInternal(protocol Protocol, lockfilePath14x, lockfilePath16x string) Interface {
	version, err := getIPTablesVersion(protocol)
	if err != nil {
		version = MinCheckVersion
	}

	if lockfilePath16x == "" {
		lockfilePath16x = LockfilePath16x
	}
	if lockfilePath14x == "" {
		lockfilePath14x = LockfilePath14x
	}

	runner := &runner{
		protocol:        protocol,
		hasCheck:        version.AtLeast(MinCheckVersion),
		hasRandomFully:  version.AtLeast(RandomFullyMinVersion),
		waitFlag:        getIPTablesWaitFlag(version),
		restoreWaitFlag: getIPTablesRestoreWaitFlag(version, protocol),
		lockfilePath14x: lockfilePath14x,
		lockfilePath16x: lockfilePath16x,
	}
	return runner
}

// New returns a new Interface which will exec iptables.
func New(protocol Protocol) Interface {
	return newInternal(protocol, "", "")
}


// EnsureChain is part of Interface.
func (runner *runner) EnsureChain(table Table, chain Chain) (bool, error) {
	fullArgs := makeFullArgs(table, chain)

	runner.mu.Lock()
	defer runner.mu.Unlock()

	out, err := runner.run(opCreateChain, fullArgs)
	if err != nil {
		switch ee := err.(type) {
		case *exec.ExitError:
			ws, ok := ee.Sys().(syscall.WaitStatus)
			if ok {
				if ee.Exited() && ws.ExitStatus() == 1 {
					return true, nil
				}
			}
			if ee.Exited() {
				return true, nil
			}
		}

		return false, fmt.Errorf("error creating chain %q: %v: %s", chain, err, out)
	}
	return false, nil
}

// FlushChain is part of Interface.
func (runner *runner) FlushChain(table Table, chain Chain) error {
	fullArgs := makeFullArgs(table, chain)

	runner.mu.Lock()
	defer runner.mu.Unlock()

	out, err := runner.run(opFlushChain, fullArgs)
	if err != nil {
		return fmt.Errorf("error flushing chain %q: %v: %s", chain, err, out)
	}
	return nil
}

// DeleteChain is part of Interface.
func (runner *runner) DeleteChain(table Table, chain Chain) error {
	fullArgs := makeFullArgs(table, chain)

	runner.mu.Lock()
	defer runner.mu.Unlock()

	// TODO: we could call iptables -S first, ignore the output and check for non-zero return (more like DeleteRule)
	out, err := runner.run(opDeleteChain, fullArgs)
	if err != nil {
		return fmt.Errorf("error deleting chain %q: %v: %s", chain, err, out)
	}
	return nil
}

// EnsureRule is part of Interface.
func (runner *runner) EnsureRule(position RulePosition, table Table, chain Chain, args ...string) (bool, error) {
	fullArgs := makeFullArgs(table, chain, args...)

	runner.mu.Lock()
	defer runner.mu.Unlock()

	exists, err := runner.checkRule(table, chain, args...)
	if err != nil {
		return false, err
	}
	if exists {
		return true, nil
	}
	out, err := runner.run(operation(position), fullArgs)
	if err != nil {
		return false, fmt.Errorf("error appending rule: %v: %s", err, out)
	}
	return false, nil
}

// DeleteRule is part of Interface.
func (runner *runner) DeleteRule(table Table, chain Chain, args ...string) error {
	fullArgs := makeFullArgs(table, chain, args...)

	runner.mu.Lock()
	defer runner.mu.Unlock()

	exists, err := runner.checkRule(table, chain, args...)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	out, err := runner.run(opDeleteRule, fullArgs)
	if err != nil {
		return fmt.Errorf("error deleting rule: %v: %s", err, out)
	}
	return nil
}

func (runner *runner) IsIPv6() bool {
	return runner.protocol == ProtocolIPv6
}

func (runner *runner) Protocol() Protocol {
	return runner.protocol
}

// SaveInto is part of Interface.
func (runner *runner) SaveInto(table Table, buffer *bytes.Buffer) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()

	// run and return
	iptablesSaveCmd := iptablesSaveCommand(runner.protocol)
	args := []string{"-t", string(table)}
	Infof("running %s %v", iptablesSaveCmd, args)
	cmd := exec.Command(iptablesSaveCmd, args...)
	cmd.Stdout = buffer
	stderrBuffer := bytes.NewBuffer(nil)
	cmd.Stderr = stderrBuffer

	err := cmd.Run()
	if err != nil {
		stderrBuffer.WriteTo(buffer) // ignore error, since we need to return the original error
	}
	return err
}

// Restore is part of Interface.
func (runner *runner) Restore(table Table, data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	// setup args
	args := []string{"-T", string(table)}
	return runner.restoreInternal(args, data, flush, counters)
}

// RestoreAll is part of Interface.
func (runner *runner) RestoreAll(data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	// setup args
	args := make([]string, 0)
	return runner.restoreInternal(args, data, flush, counters)
}

type iptablesLocker interface {
	Close() error
}

// restoreInternal is the shared part of Restore/RestoreAll
func (runner *runner) restoreInternal(args []string, data []byte, flush FlushFlag, counters RestoreCountersFlag) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()


	if !flush {
		args = append(args, "--noflush")
	}
	if counters {
		args = append(args, "--counters")
	}

	// Grab the iptables lock to prevent iptables-restore and iptables
	// from stepping on each other.  iptables-restore 1.6.2 will have
	// a --wait option like iptables itself, but that's not widely deployed.
	if len(runner.restoreWaitFlag) == 0 {
		locker, err := grabIptablesLocks(runner.lockfilePath14x, runner.lockfilePath16x)
		if err != nil {
			return err
		}
		defer func(locker iptablesLocker) {
			if err := locker.Close(); err != nil {
			}
		}(locker)
	}

	// run the command and return the output or an error including the output and error
	fullArgs := append(runner.restoreWaitFlag, args...)
	iptablesRestoreCmd := iptablesRestoreCommand(runner.protocol)
	Infof("running %s %v", iptablesRestoreCmd, fullArgs)
	cmd := exec.Command(iptablesRestoreCmd, fullArgs...)
	cmd.Stdin = bytes.NewBuffer(data)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v (%s)", err, b)
	}
	return nil
}

func iptablesSaveCommand(protocol Protocol) string {
	if protocol == ProtocolIPv6 {
		return cmdIP6TablesSave
	}
	return cmdIPTablesSave
}

func iptablesRestoreCommand(protocol Protocol) string {
	if protocol == ProtocolIPv6 {
		return cmdIP6TablesRestore
	}
	return cmdIPTablesRestore

}

func iptablesCommand(protocol Protocol) string {
	if protocol == ProtocolIPv6 {
		return cmdIP6Tables
	}
	return cmdIPTables
}

func (runner *runner) run(op operation, args []string) ([]byte, error) {
	return runner.runContext(context.TODO(), op, args)
}

func (runner *runner) runContext(ctx context.Context, op operation, args []string) ([]byte, error) {
	iptablesCmd := iptablesCommand(runner.protocol)
	fullArgs := append(runner.waitFlag, string(op))
	fullArgs = append(fullArgs, args...)
	Infof("running iptables: %s %v", iptablesCmd, fullArgs)
	if ctx == nil {
		return exec.Command(iptablesCmd, fullArgs...).CombinedOutput()
	}
	return exec.CommandContext(ctx, iptablesCmd, fullArgs...).CombinedOutput()
	// Don't log err here - callers might not think it is an error.
}

// Returns (bool, nil) if it was able to check the existence of the rule, or
// (<undefined>, error) if the process of checking failed.
func (runner *runner) checkRule(table Table, chain Chain, args ...string) (bool, error) {
	if runner.hasCheck {
		return runner.checkRuleUsingCheck(makeFullArgs(table, chain, args...))
	}
	return runner.checkRuleWithoutCheck(table, chain, args...)
}

var hexnumRE = regexp.MustCompile("0x0+([0-9])")

func trimhex(s string) string {
	return hexnumRE.ReplaceAllString(s, "0x$1")
}

// Executes the rule check without using the "-C" flag, instead parsing iptables-save.
// Present for compatibility with <1.4.11 versions of iptables.  This is full
// of hack and half-measures.  We should nix this ASAP.
func (runner *runner) checkRuleWithoutCheck(table Table, chain Chain, args ...string) (bool, error) {
	iptablesSaveCmd := iptablesSaveCommand(runner.protocol)
	Infof("running %s -t %s", iptablesSaveCmd, string(table))
	out, err := exec.Command(iptablesSaveCmd, "-t", string(table)).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("error checking rule: %v", err)
	}

	// Sadly, iptables has inconsistent quoting rules for comments. Just remove all quotes.
	// Also, quoted multi-word comments (which are counted as a single arg)
	// will be unpacked into multiple args,
	// in order to compare against iptables-save output (which will be split at whitespace boundary)
	// e.g. a single arg('"this must be before the NodePort rules"') will be unquoted and unpacked into 7 args.
	var argsCopy []string
	for i := range args {
		tmpField := strings.Trim(args[i], "\"")
		tmpField = trimhex(tmpField)
		argsCopy = append(argsCopy, strings.Fields(tmpField)...)
	}
	argset := pkg.NewString(argsCopy...)

	for _, line := range strings.Split(string(out), "\n") {
		var fields = strings.Fields(line)

		// Check that this is a rule for the correct chain, and that it has
		// the correct number of argument (+2 for "-A <chain name>")
		if !strings.HasPrefix(line, fmt.Sprintf("-A %s", string(chain))) || len(fields) != len(argsCopy)+2 {
			continue
		}

		// Sadly, iptables has inconsistent quoting rules for comments.
		// Just remove all quotes.
		for i := range fields {
			fields[i] = strings.Trim(fields[i], "\"")
			fields[i] = trimhex(fields[i])
		}

		// TODO: This misses reorderings e.g. "-x foo ! -y bar" will match "! -x foo -y bar"
		if pkg.NewString(fields...).IsSuperset(argset) {
			return true, nil
		}
		Infof("DBG: fields is not a superset of args: fields=%v  args=%v", fields, args)
	}

	return false, nil
}

// Executes the rule check using the "-C" flag
func (runner *runner) checkRuleUsingCheck(args []string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out, err := runner.runContext(ctx, opCheckRule, args)
	if ctx.Err() == context.DeadlineExceeded {
		return false, fmt.Errorf("timed out while checking rules")
	}
	if err == nil {
		return true, nil
	}
	switch ee := err.(type) {
	case *exec.ExitError:
		ws, ok := ee.Sys().(syscall.WaitStatus)
		if ok {
			if ee.Exited() && ws.ExitStatus() == 1 {
				return false, nil
			}
		}
		if ee.Exited() {
			return false, nil
		}
	}
	return false, fmt.Errorf("error checking rule: %v: %s", err, out)
}

const (
	// Max time we wait for an iptables flush to complete after we notice it has started
	iptablesFlushTimeout = 5 * time.Second
	// How often we poll while waiting for an iptables flush to complete
	iptablesFlushPollTime = 100 * time.Millisecond
)

func (runner *runner) CheckRule(table Table, chain Chain, args ...string) (bool, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.checkRule(table, chain, args...)

}

// ChainExists is part of Interface
func (runner *runner) ChainExists(table Table, chain Chain) (bool, error) {
	fullArgs := makeFullArgs(table, chain)

	runner.mu.Lock()
	defer runner.mu.Unlock()

	_, err := runner.run(opListChain, fullArgs)
	return err == nil, err
}

type operation string

const (
	opCreateChain operation = "-N"
	opFlushChain  operation = "-F"
	opDeleteChain operation = "-X"
	opListChain   operation = "-S"
	opCheckRule   operation = "-C"
	opDeleteRule  operation = "-D"
)

func makeFullArgs(table Table, chain Chain, args ...string) []string {
	return append([]string{string(chain), "-t", string(table)}, args...)
}

const iptablesVersionPattern = `v([0-9]+(\.[0-9]+)+)`

// getIPTablesVersion runs "iptables --version" and parses the returned version
func getIPTablesVersion(protocol Protocol) (*pkg.Version, error) {
	// this doesn't access mutable state so we don't need to use the interface / runner
	iptablesCmd := iptablesCommand(protocol)
	bytes, err := exec.Command(iptablesCmd, "--version").CombinedOutput()
	if err != nil {
		return nil, err
	}
	versionMatcher := regexp.MustCompile(iptablesVersionPattern)
	match := versionMatcher.FindStringSubmatch(string(bytes))
	if match == nil {
		return nil, fmt.Errorf("no iptables version found in string: %s", bytes)
	}
	version, err := pkg.ParseGeneric(match[1])
	if err != nil {
		return nil, fmt.Errorf("iptables version %q is not a valid version string: %v", match[1], err)
	}

	return version, nil
}

// Checks if iptables version has a "wait" flag
func getIPTablesWaitFlag(version *pkg.Version) []string {
	switch {
	case version.AtLeast(WaitIntervalMinVersion):
		return []string{WaitString, WaitSecondsValue, WaitIntervalString, WaitIntervalUsecondsValue}
	case version.AtLeast(WaitSecondsMinVersion):
		return []string{WaitString, WaitSecondsValue}
	case version.AtLeast(WaitMinVersion):
		return []string{WaitString}
	default:
		return nil
	}
}

// Checks if iptables-restore has a "wait" flag
func getIPTablesRestoreWaitFlag(version *pkg.Version, protocol Protocol) []string {
	if version.AtLeast(WaitRestoreMinVersion) {
		return []string{WaitString, WaitSecondsValue, WaitIntervalString, WaitIntervalUsecondsValue}
	}

	// Older versions may have backported features; if iptables-restore supports
	// --version, assume it also supports --wait
	vstring, err := getIPTablesRestoreVersionString(protocol)
	if err != nil || vstring == "" {
		Infof("couldn't get iptables-restore version; assuming it doesn't support --wait")
		return nil
	}
	if _, err := pkg.ParseGeneric(vstring); err != nil {
		Infof("couldn't parse iptables-restore version; assuming it doesn't support --wait")
		return nil
	}
	return []string{WaitString}
}

// getIPTablesRestoreVersionString runs "iptables-restore --version" to get the version string
// in the form "X.X.X"
func getIPTablesRestoreVersionString(protocol Protocol) (string, error) {
	// this doesn't access mutable state so we don't need to use the interface / runner

	// iptables-restore hasn't always had --version, and worse complains
	// about unrecognized commands but doesn't exit when it gets them.
	// Work around that by setting stdin to nothing so it exits immediately.
	iptablesRestoreCmd := iptablesRestoreCommand(protocol)
	cmd := exec.Command(iptablesRestoreCmd, "--version")
	cmd.Stdin = bytes.NewReader([]byte{})
	bytes, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	versionMatcher := regexp.MustCompile(iptablesVersionPattern)
	match := versionMatcher.FindStringSubmatch(string(bytes))
	if match == nil {
		return "", fmt.Errorf("no iptables version found in string: %s", bytes)
	}
	return match[1], nil
}

func (runner *runner) HasRandomFully() bool {
	return runner.hasRandomFully
}

var iptablesNotFoundStrings = []string{
	// iptables-legacy [-A|-I] BAD-CHAIN [...]
	// iptables-legacy [-C|-D] GOOD-CHAIN [...non-matching rule...]
	// iptables-legacy [-X|-F|-Z] BAD-CHAIN
	// iptables-nft -X BAD-CHAIN
	// NB: iptables-nft [-F|-Z] BAD-CHAIN exits with no error
	"No chain/target/match by that name",

	// iptables-legacy [...] -j BAD-CHAIN
	// iptables-nft-1.8.0 [-A|-I] BAD-CHAIN [...]
	// iptables-nft-1.8.0 [-A|-I] GOOD-CHAIN -j BAD-CHAIN
	// NB: also matches some other things like "-m BAD-MODULE"
	"No such file or directory",

	// iptables-legacy [-C|-D] BAD-CHAIN [...]
	// iptables-nft [-C|-D] GOOD-CHAIN [...non-matching rule...]
	"does a matching rule exist",

	// iptables-nft-1.8.2 [-A|-C|-D|-I] BAD-CHAIN [...]
	// iptables-nft-1.8.2 [...] -j BAD-CHAIN
	"does not exist",
}

// IsNotFoundError returns true if the error indicates "not found".  It parses
// the error string looking for known values, which is imperfect; beware using
// this function for anything beyond deciding between logging or ignoring an
// error.
func IsNotFoundError(err error) bool {
	es := err.Error()
	for _, str := range iptablesNotFoundStrings {
		if strings.Contains(es, str) {
			return true
		}
	}
	return false
}

const iptablesStatusResourceProblem = 4
