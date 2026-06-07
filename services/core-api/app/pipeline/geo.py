"""Geo helpers for velocity-based identity analysis (impossible travel)."""
from __future__ import annotations

import math

EARTH_RADIUS_KM = 6371.0
# Commercial flight cruise (~900 km/h) plus airport/transfer overhead. Above this
# implied speed between two logins, the travel is physically implausible.
MAX_FEASIBLE_KMH = 900.0


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlam / 2) ** 2
    return 2 * EARTH_RADIUS_KM * math.asin(min(1.0, math.sqrt(a)))


def implied_speed_kmh(km: float, seconds: float) -> float:
    if seconds <= 0:
        return float("inf")
    return km / (seconds / 3600.0)
