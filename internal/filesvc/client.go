package filesvc

import _ "embed"

// ClientScript runs in memory in the relay's python3, with no installed package.
//
//go:embed client.py
var ClientScript string
