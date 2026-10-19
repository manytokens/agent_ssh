//go:build !windows

package platform

func ConsoleInput() (func(string) error, bool) { return nil, false }
