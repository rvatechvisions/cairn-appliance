module github.com/rvatechvisions/cairn-appliance/preflight

go 1.22

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
