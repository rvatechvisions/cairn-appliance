module github.com/rvatechvisions/cairn-appliance/preflight

go 1.26.0

// NO REQUIRE LINE, DELIBERATELY. `go mod tidy` writes it, from the imports in
// main.go, with a real version and a checksum.
//
// A version written from memory is a fabricated identifier in the one place
// where being wrong is silent: a module that does not exist fails loudly, and a
// module version that exists but is not the one anybody meant does not.
//
// The first version of this file tried to have it both ways -- it said nothing
// was pinned and then pinned `v0.0.0`, which is not a version anybody publishes.
// The result was that `go build` refused with five "missing go.sum entry"
// errors naming packages that were imported correctly, and the reader was sent
// looking at the imports rather than at the line that had invented a version.
// An empty requirement is what "not pinned" actually looks like.

require (
	github.com/oiweiwei/go-msrpc v1.6.4
	github.com/oiweiwei/gokrb5.fork/v9 v9.0.8
	github.com/rs/zerolog v1.35.1
)

require (
	github.com/geoffgarside/ber v1.1.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/indece-official/go-ebcdic v1.2.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/oiweiwei/go-math v1.0.0 // indirect
	github.com/oiweiwei/go-oem v1.0.0 // indirect
	github.com/oiweiwei/go-smb2.fork v1.0.2 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
