// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package x_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/x"
)

func Test_HaversineDistance(t *testing.T) {
	type TestCase struct {
		lat1, lon1, lat2, lon2, expected float64
	}

	testCases := []TestCase{
		{48.1375, 11.5750, 41.3828, 2.1769, 1_054_327},    // Munich to Barcelona
		{41.3828, 2.1769, -34.6033, -58.3817, 10_465_777}, // Barcelona to Buenos Aires
		{48.1375, 11.5750, 47.1667, 9.5097, 188_628},      // Munich to Liechtenstein
	}

	for _, tc := range testCases {
		d := x.HaversineDistance(tc.lat1, tc.lon1, tc.lat2, tc.lon2)
		errorRate := math.Abs(d-tc.expected) / tc.expected

		require.LessOrEqual(t, errorRate, 0.0001, "HaversineDistance(%f, %f, %f, %f) = %f, expected %f", tc.lat1, tc.lon1, tc.lat2, tc.lon2, d, tc.expected)
	}
}
