module github.com/spiegel-im-spiegel/gpgpdump

go 1.15

require (
	github.com/spf13/cobra v1.1.1
	github.com/spiegel-im-spiegel/errs v1.0.2
	github.com/spiegel-im-spiegel/gocli v0.10.3
	golang.org/x/crypto v0.0.0-20201208171446-5f87f3452ae9
)

replace github.com/coreos/etcd v3.3.13+incompatible => github.com/coreos/etcd v3.3.25+incompatible
