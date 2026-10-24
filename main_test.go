package main

import (
	"strings"
	"testing"
)

func TestGeneratePasswordLengths(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"min length", 8},
		{"default length", 16},
		{"long password", 32},
		{"very long password", 64},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Length:     tt.length,
				AllowLower: true,
			}

			password, err := generatePassword(cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(password) != tt.length {
				t.Errorf(
					"want length %d, got %d",
					tt.length,
					len(password),
				)
			}
		})
	}
}

func TestGeneratePasswordInvalidLength(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"minus length", 0},
		{"zero length", -1},
		{"less min length", 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				Length:     tt.length,
				AllowLower: true,
			}

			password, err := generatePassword(cfg)
			if err == nil {
				t.Errorf(
					"waited error for length: %d, got value %s",
					tt.length,
					password,
				)
			}
			if err.Error() != "password length must be at least 8" {
				t.Errorf(
					"waited error: %s, got error: %s",
					"password length must be at least 8",
					err.Error(),
				)
			}
		})
	}
}

func TestGeneratePasswordNoGroups(t *testing.T) {
	t.Run("no groups", func(t *testing.T) {
		cfg := Config{
			Length:       8,
			AllowLower:   false,
			AllowSymbols: false,
			AllowNumbers: false,
			AllowUpper:   false,
		}

		password, err := generatePassword(cfg)

		if err == nil {
			t.Errorf(
				"waited error but, got value %s",
				password,
			)
		}
		if err.Error() != "no groups specified" {
			t.Errorf(
				"waited error: %s, got error: %s",
				"no groups specified",
				err.Error(),
			)
		}
	})
}

func hasSymbol(symbol string, groups []string) bool {
	for _, group := range groups {
		if strings.Contains(group, symbol) {
			return true
		}
	}

	return false
}

func TestGeneratePasswordAllowedCharacters(t *testing.T) {
	tests := []struct {
		name          string
		allowedGroups []string
		config        Config
	}{
		{
			"lower only",
			[]string{lowerLetters},
			Config{
				Length:       8,
				AllowLower:   true,
				AllowSymbols: false,
				AllowNumbers: false,
				AllowUpper:   false,
			},
		},
		{
			"upper only",
			[]string{upperLetters},
			Config{
				Length:       8,
				AllowLower:   false,
				AllowSymbols: false,
				AllowNumbers: false,
				AllowUpper:   true,
			},
		},
		{
			"numbers only",
			[]string{numbers},
			Config{
				Length:       8,
				AllowLower:   false,
				AllowSymbols: false,
				AllowNumbers: true,
				AllowUpper:   false,
			},
		},
		{
			"symbols only",
			[]string{symbols},
			Config{
				Length:       8,
				AllowLower:   false,
				AllowSymbols: true,
				AllowNumbers: false,
				AllowUpper:   false,
			},
		},
		{
			"letters only",
			[]string{lowerLetters, upperLetters},
			Config{
				Length:       8,
				AllowLower:   true,
				AllowSymbols: false,
				AllowNumbers: false,
				AllowUpper:   true,
			},
		},
		{
			"letters and numbers",
			[]string{lowerLetters, upperLetters, numbers},
			Config{
				Length:       8,
				AllowLower:   true,
				AllowSymbols: false,
				AllowNumbers: true,
				AllowUpper:   true,
			},
		},
		{
			"letters and numbers and symbols",
			[]string{lowerLetters, upperLetters, numbers, symbols},
			Config{
				Length:       8,
				AllowLower:   true,
				AllowSymbols: true,
				AllowNumbers: true,
				AllowUpper:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			password, err := generatePassword(tt.config)
			if err != nil {
				t.Errorf(
					"waited value, got error %s",
					err.Error(),
				)
			}

			for i := 0; i < len(password); i++ {
				symbol := string(password[i])

				if !hasSymbol(symbol, tt.allowedGroups) {
					t.Errorf(
						"symbol %s not allowed for groups in case %s",
						symbol,
						tt.name,
					)
					break
				}
			}
		})
	}
}
