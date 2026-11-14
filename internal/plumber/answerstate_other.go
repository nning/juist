//go:build unix && !darwin

package plumber

// answerState is how pf keeps the state of what comes in by another device:
// sloppily, so that a connection older than the anchor is kept.
const answerState = "keep state (sloppy)"
