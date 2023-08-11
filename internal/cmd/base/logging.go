// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/boundary/internal/cmd/base/logging"
	"github.com/hashicorp/go-hclog"
)

func ProcessLogLevelAndFormat(flagLogLevel, flagLogFormat, configLogLevel, configLogFormat string) (hclog.Level, logging.LogFormat, error) {
	logFormat := logging.UnspecifiedFormat

	// If the flag wasn't set, check config; if not set use info
	logLevel := strings.ToLower(strings.TrimSpace(flagLogLevel))
	if logLevel == "" {
		logLevel = strings.ToLower(strings.TrimSpace(configLogLevel))
		if logLevel == "" {
			logLevel = "info"
		}
	}

	// Set level based off text value
	var level hclog.Level
	switch logLevel {
	case "trace":
		level = hclog.Trace
	case "debug":
		level = hclog.Debug
	case "notice", "info":
		level = hclog.Info
	case "warn", "warning":
		level = hclog.Warn
	case "err", "error":
		level = hclog.Error
	default:
		return level, logFormat, fmt.Errorf("unknown log level: %s", logLevel)
	}

	if flagLogFormat != "" {
		var err error
		logFormat, err = logging.ParseLogFormat(flagLogFormat)
		if err != nil {
			return level, logFormat, err
		}
	}
	if logFormat == logging.UnspecifiedFormat {
		var err error
		logFormat, err = logging.ParseLogFormat(configLogFormat)
		if err != nil {
			return level, logFormat, err
		}
	}

	return level, logFormat, nil
}

type GRPCLogFaker struct {
	Logger hclog.Logger
	Log    bool
}

func (g *GRPCLogFaker) Fatal(args ...any) {
	g.Logger.Error(fmt.Sprint(args...))
	os.Exit(1)
}

func (g *GRPCLogFaker) Fatalf(format string, args ...any) {
	g.Logger.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func (g *GRPCLogFaker) Fatalln(args ...any) {
	g.Logger.Error(fmt.Sprintln(args...))
	os.Exit(1)
}

func (g *GRPCLogFaker) Print(args ...any) {
	if g.Log && g.Logger.IsDebug() {
		g.Logger.Debug(fmt.Sprint(args...))
	}
}

func (g *GRPCLogFaker) Printf(format string, args ...any) {
	if g.Log && g.Logger.IsDebug() {
		g.Logger.Debug(fmt.Sprintf(format, args...))
	}
}

func (g *GRPCLogFaker) Println(args ...any) {
	if g.Log && g.Logger.IsDebug() {
		g.Logger.Debug(fmt.Sprintln(args...))
	}
}
