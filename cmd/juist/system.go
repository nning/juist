package main

import "github.com/nning/juist/cmd/internal/defaults"

// systemHome is the packaged service's state directory. Its existence says
// the service is installed, whether or not it runs.
const systemHome = defaults.SystemHome
