// Package config provides configurable settings for bsw with environment
// variable overrides and sensible defaults.
package config

import (
	"os"
	"strconv"
	"time"
)

// Default timeout values.
const (
	DefaultStaleTimeout  = 10 * time.Minute
	DefaultDoctorTimeout = 15 * time.Second
	DefaultReviewTimeout = 90 * time.Second
)

// StaleTimeout returns the stale worker detection threshold.
// Override with BSW_STALE_TIMEOUT_SEC.
func StaleTimeout() time.Duration {
	return durationFromEnvSec("BSW_STALE_TIMEOUT_SEC", DefaultStaleTimeout)
}

// DoctorTimeout returns the timeout for health checks in bsw doctor.
// Override with BSW_DOCTOR_TIMEOUT_SEC.
func DoctorTimeout() time.Duration {
	return durationFromEnvSec("BSW_DOCTOR_TIMEOUT_SEC", DefaultDoctorTimeout)
}

// ReviewTimeout returns the default review timeout in seconds (for flag default).
// Override with BSW_REVIEW_TIMEOUT_SEC.
func ReviewTimeoutSec() int {
	return intFromEnv("BSW_REVIEW_TIMEOUT_SEC", int(DefaultReviewTimeout/time.Second))
}

func durationFromEnvSec(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	sec, err := strconv.Atoi(v)
	if err != nil || sec < 0 {
		return fallback
	}
	return time.Duration(sec) * time.Second
}

func intFromEnv(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}
