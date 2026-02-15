// Copyright 2026 The Rampart Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package proxy

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	decisionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "rampart_decisions_total",
			Help: "Total number of policy decisions by action and policy.",
		},
		[]string{"action", "policy"},
	)

	evalDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name: "rampart_eval_duration_seconds",
			Help: "Policy evaluation duration in seconds.",
			Buckets: []float64{
				0.000001, 0.000005, 0.00001, 0.00005,
				0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1,
			},
		},
	)

	pendingApprovals = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "rampart_pending_approvals",
			Help: "Current number of pending approval requests.",
		},
	)

	policyCount = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "rampart_policy_count",
			Help: "Current number of loaded policies.",
		},
	)

	uptimeSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "rampart_uptime_seconds",
			Help: "Seconds since the proxy server started.",
		},
	)

	metricsRegistry = prometheus.NewRegistry()
)

func init() {
	metricsRegistry.MustRegister(
		decisionsTotal,
		evalDuration,
		pendingApprovals,
		policyCount,
		uptimeSeconds,
		prometheus.NewGoCollector(),
		prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
	)
}

// RecordDecision records a policy decision for Prometheus metrics.
func RecordDecision(action, policy string, duration time.Duration) {
	if policy == "" {
		policy = "none"
	}
	decisionsTotal.With(prometheus.Labels{"action": action, "policy": policy}).Inc()
	evalDuration.Observe(duration.Seconds())
}

// SetPendingApprovals sets the current pending approvals gauge.
func SetPendingApprovals(n int) {
	pendingApprovals.Set(float64(n))
}

// SetPolicyCount sets the current policy count gauge.
func SetPolicyCount(n int) {
	policyCount.Set(float64(n))
}

// SetUptime sets the uptime gauge in seconds.
func SetUptime(d time.Duration) {
	uptimeSeconds.Set(d.Seconds())
}

// MetricsHandler returns an HTTP handler for the /metrics endpoint.
func MetricsHandler() http.Handler {
	return promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{})
}
