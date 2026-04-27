// Copyright (C) 2026 Algorand, Inc.
//
// Build with `go build -tags gibbs ./...` to enable the Gibbs sampler keygen
// path (Sun et al., PQCrypto 2026; see gibbs-research-plan.md). Without this
// tag the package builds the standard rejection-sampling keygen and is
// bit-identical to the upstream release. cgo CFLAGS lines from all files in
// the package accumulate, so this file's `-DFALCON_GIBBS_KEYGEN=1` is added
// to the flags declared in falcon.go.
//
// Keys produced by the Gibbs path use alpha = 1.04 (vs. FALCON's 1.17), so
// they are NOT interoperable with mainnet FALCON verifiers — they are
// research-only.

//go:build gibbs

package falcon

//#cgo CFLAGS: -DFALCON_GIBBS_KEYGEN=1
import "C"
