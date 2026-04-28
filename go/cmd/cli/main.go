// Package main implements the VIBAP CLI tool.
//
// Usage:
//
//	vibap credential create [flags]   — Issue a new VIBAP credential
//	vibap credential verify [flags]   — Verify an existing credential
//	vibap credential inspect [flags]  — Decode and display credential contents
//	vibap keygen [flags]              — Generate an Ed25519 signing keypair
//	vibap version                     — Print version information
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-phase1"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "credential":
		runCredential(os.Args[2:])
	case "keygen":
		runKeygen(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("vibap %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func runCredential(args []string) {
	if len(args) < 1 {
		printCredentialUsage()
		os.Exit(1)
	}

	switch args[0] {
	case "create":
		runCreate(args[1:])
	case "verify":
		runVerify(args[1:])
	case "inspect":
		runInspect(args[1:])
	case "help", "--help", "-h":
		printCredentialUsage()
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown credential subcommand %q\n\n", args[0])
		printCredentialUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `vibap — Verifiable Identity-Bound Agent Passport CLI

Usage:
  vibap <command> [subcommand] [flags]

Commands:
  credential create   Issue a new VIBAP SD-JWT-VC credential
  credential verify   Verify an existing credential
  credential inspect  Decode and display credential contents
  keygen              Generate an Ed25519 signing keypair
  version             Print version information
  help                Show this help message

Examples:
  # Generate a signing keypair
  vibap keygen --output issuer-key.json

  # Create a credential with demo data
  vibap credential create --demo --key-file issuer-key.json

  # Verify a credential
  vibap credential verify --key-file issuer-key.json --input credential.jwt

  # Inspect credential contents (no signature check)
  vibap credential inspect --input credential.jwt

`)
}

func printCredentialUsage() {
	fmt.Fprintf(os.Stderr, `vibap credential — Manage VIBAP SD-JWT-VC credentials

Usage:
  vibap credential <subcommand> [flags]

Subcommands:
  create    Issue a new VIBAP credential
  verify    Verify a credential's signature, claims, and status
  inspect   Decode and display credential contents (no verification)

Run 'vibap credential <subcommand> --help' for subcommand-specific flags.
`)
}
