package main

import (
	"github.com/threatprism/threatprism/internal/buildinfo"
	"github.com/threatprism/threatprism/internal/cli"
)

func main() {
	cli.Execute(buildinfo.Version)
}
