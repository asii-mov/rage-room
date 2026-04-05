#!/usr/bin/env bash
# Go module supply-chain hardening
# Ensures all modules are fetched through the official proxy with checksum verification
# The ",off" suffix means: if the proxy doesn't have it, fail (don't fall back to direct)

export GOPROXY="proxy.golang.org,off"
export GOSUMDB="sum.golang.org"
