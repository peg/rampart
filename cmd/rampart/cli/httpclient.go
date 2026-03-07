// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License").

package cli

import (
	"net/http"
	"time"
)

// rampartHTTPClient is used for all outgoing HTTP requests from CLI commands
// (hook, approve, etc). The timeout prevents hangs when the Rampart server
// is unresponsive — without it, a stuck proxy blocks Claude indefinitely.
var rampartHTTPClient = &http.Client{Timeout: 10 * time.Second}
