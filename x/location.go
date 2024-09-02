// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package x

import "math"

const (
	earthRadius = 6_371_000 // Earth's radius in meters
)

func ToRad(deg float64) float64 {
	return deg * math.Pi / 180
}

// HaversineDistance calculates the distance between two points on the surface of a sphere in meters
// using the Haversine formula
// https://en.wikipedia.org/wiki/Haversine_formula
func HaversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	dLat := ToRad(lat2 - lat1)
	dLon := ToRad(lon2 - lon1)

	lat1 = ToRad(lat1)
	lat2 = ToRad(lat2)

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Sin(dLon/2)*math.Sin(dLon/2)*math.Cos(lat1)*math.Cos(lat2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}
