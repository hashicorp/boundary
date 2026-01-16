// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github.com/hashicorp/boundary/internal/cmd/base/logging"
	"github.com/hashicorp/go-hclog"
	"google.golang.org/grpc/grpclog"
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

type grpcLogFakerLogHolder struct {
	logger hclog.Logger
}

var grpcLogFaker *GRPCLogFaker = &GRPCLogFaker{
	loggingEnabled: new(atomic.Bool),
	logger:         new(atomic.Pointer[grpcLogFakerLogHolder]),
}

func init() {
	grpclog.SetLoggerV2(grpcLogFaker)
}

type GRPCLogFaker struct {
	logger         *atomic.Pointer[grpcLogFakerLogHolder]
	loggingEnabled *atomic.Bool
}

func (g *GRPCLogFaker) SetLogOnOff(on bool) {
	g.loggingEnabled.Store(on)
}

func (g *GRPCLogFaker) SetLogger(logger hclog.Logger) {
	g.logger.Store(&grpcLogFakerLogHolder{logger: logger})
}

func (g *GRPCLogFaker) Fatal(args ...any) {
	if l := g.logger.Load(); l != nil {
		l.logger.Error(fmt.Sprint(args...))
	}
	os.Exit(1)
}

func (g *GRPCLogFaker) Fatalf(format string, args ...any) {
	if l := g.logger.Load(); l != nil {
		l.logger.Error(fmt.Sprintf(format, args...))
	}
	os.Exit(1)
}

func (g *GRPCLogFaker) Fatalln(args ...any) {
	if l := g.logger.Load(); l != nil {
		l.logger.Error(fmt.Sprintln(args...))
	}
	os.Exit(1)
}

func (g *GRPCLogFaker) Info(args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprint(args...))
			}
		}
	}
}

func (g *GRPCLogFaker) Infof(format string, args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprintf(format, args...))
			}
		}
	}
}

func (g *GRPCLogFaker) Infoln(args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprintln(args...))
			}
		}
	}
}

func (g *GRPCLogFaker) Warning(args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprint(args...))
			}
		}
	}
}

func (g *GRPCLogFaker) Warningf(format string, args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprintf(format, args...))
			}
		}
	}
}

func (g *GRPCLogFaker) Warningln(args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprintln(args...))
			}
		}
	}
}

func (g *GRPCLogFaker) Error(args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprint(args...))
			}
		}
	}
}

func (g *GRPCLogFaker) Errorf(format string, args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprintf(format, args...))
			}
		}
	}
}

func (g *GRPCLogFaker) Errorln(args ...any) {
	if g.loggingEnabled.Load() {
		if l := g.logger.Load(); l != nil {
			if l.logger.IsDebug() {
				l.logger.Debug(fmt.Sprintln(args...))
			}
		}
	}
}

func (g *GRPCLogFaker) V(l int) bool {
	return true
}
