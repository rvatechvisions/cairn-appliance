module github.com/rvatechvisions/cairn-appliance/preflight

go 1.22

// No versions are pinned here, and the first `go mod tidy` will write them.
//
// A version written from memory is a fabricated identifier in the one place
// where being wrong is silent: a module that does not exist fails loudly, and a
// module version that exists but is not the one anybody meant does not.
require github.com/oiweiwei/go-msrpc v0.0.0
