module github.com/rvatechvisions/cairn-appliance/preflight

go 1.26.0

toolchain go1.27.1

// THE VERSIONS BELOW WERE WRITTEN BY THE MODULE TIDY STEP, NOT BY A PERSON, AND THAT
// IS THE WHOLE POINT OF THEM.
//
// A version written from memory is a fabricated identifier in the one place
// where being wrong is silent: a module that does not exist fails loudly, and a
// module version that exists but is not the one anybody meant does not. So the
// requires and the checksums in go.sum were resolved once, from the imports in
// main.go, against the module proxy -- and then committed, which is what turns
// a resolution into a pin.
//
// **This comment used to say there was deliberately no require line**, which
// was true before the pin and was left sitting directly above two require
// blocks that contradicted it. A superseded design survives in the text beside
// the thing that changed, because a rewrite is prompted by the sentence that
// now reads falsely and nobody rereads the paragraph above the diff.
//
// The history worth keeping: the first version tried to have it both ways --
// it said nothing was pinned and then pinned `v0.0.0`, which is not a version
// anybody publishes. `go build` refused with five "missing go.sum entry"
// errors naming packages that were imported correctly, and the reader was sent
// looking at the imports rather than at the line that had invented a version.
//
// To change a version here: change it in one place, run the build, and let the
// proxy refuse it if it does not exist. Do not hand-edit go.sum.

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
