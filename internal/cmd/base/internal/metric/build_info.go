// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

// Package metric provides functions to initialize a prometheus metric
// detailing build info
package metric

import (
	"runtime"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/version"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	labelGoVersion       = "goversion"
	labelGitRevision     = "revision"
	labelBoundaryVersion = "version"
)

// buildInfoVec is a gauge metric whose value is always equal to 1 and whose
// labels contain the current go version, git revision, and boundary version.
var buildInfoVec = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Namespace: globals.MetricNamespace,
		Name:      "build_info",
		Help:      "Gauge with labels describing go version, git revision hash, and Boundary release version.",
	},
	[]string{labelGoVersion, labelGitRevision, labelBoundaryVersion},
)

func getBuildInfoLabels() map[string]string {
	verInfo := version.Get()

	return map[string]string{
		labelGoVersion:       runtime.Version(),
		labelGitRevision:     verInfo.Revision,
		labelBoundaryVersion: verInfo.Version,
	}
}

// InitializeBuildInfo registers the boundary_build_info metric with its
// correct labels and sets its value to 1.
func InitializeBuildInfo(r prometheus.Registerer) {
	if r == nil {
		return
	}

	r.MustRegister(buildInfoVec)
	l := prometheus.Labels(getBuildInfoLabels())
	buildInfoVec.With(l).Set(float64(1))
}
