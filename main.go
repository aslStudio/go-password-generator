package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"
)

type Config struct {
	Length       int
	AllowLower   bool
	AllowUpper   bool
	AllowNumbers bool
	AllowSymbols bool
}

func main() {
	var length = flag.Int("length", 16, "length of password")
	var allowLower = flag.Bool("lower-letters", true, "allow lowercase letters")
	var allowUpper = flag.Bool("upper-letters", true, "allow uppercase letters")
	var allowNumbers = flag.Bool("numbers", true, "allow numbers")
	var allowSymbols = flag.Bool("symbols", true, "allow symbols")
	flag.Parse()

	config := Config{
		Length:       *length,
		AllowLower:   *allowLower,
		AllowUpper:   *allowUpper,
		AllowNumbers: *allowNumbers,
		AllowSymbols: *allowSymbols,
	}

	password, err := generatePassword(config)

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	fmt.Println(password)
}

const (
	lowerLetters = "abcdefghijklmnopqrstuvwxyz"
	upperLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers      = "0123456789"
	symbols      = "!@#$%^&*()_+-={}[]\\|<,>.?/"
)

func generatePassword(config Config) (string, error) {
	var result strings.Builder
	groups := ""

	if config.Length < 8 {
		return "", errors.New("password length must be at least 8")
	}

	if config.AllowLower {
		groups += lowerLetters
	}
	if config.AllowUpper {
		groups += upperLetters
	}
	if config.AllowNumbers {
		groups += numbers
	}
	if config.AllowSymbols {
		groups += symbols
	}

	if len(groups) == 0 {
		return "", errors.New("no groups specified")
	}

	for range config.Length {
		symbol, err := rand.Int(
			rand.Reader,
			big.NewInt(int64(len(groups))),
		)

		if err != nil {
			return "", fmt.Errorf("failed to generate symbol: %w", err)
		}

		selectedSymbolIndex := symbol.Int64()

		result.WriteString(string(groups[selectedSymbolIndex]))
	}

	return result.String(), nil
}
