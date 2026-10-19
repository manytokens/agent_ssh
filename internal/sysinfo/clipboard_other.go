//go:build !windows

package sysinfo

import (
	"context"
	"errors"
)

func clipboardGet(context.Context) (string, error) {
	return "", errors.New("clipboard is currently supported on Windows only")
}
func clipboardSet(context.Context, string) error {
	return errors.New("clipboard is currently supported on Windows only")
}
