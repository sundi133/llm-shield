"""Real geofences: lat/lon polygons, inclusion and exclusion, leg-aware.

A zone allowlist of string names is not a geofence, and an engineer will say so.
A geofence is a polygon of surveyed coordinates with a type, which is what
MAVLink carries (`Polygon(points=[Point(lat, lon)], FenceType.INCLUSION |
EXCLUSION)`) and what PX4 enforces onboard.

This checks the same geometry Shield would check before a command is uploaded,
and it checks the LEG rather than only the endpoint. A waypoint outside an
exclusion zone is not sufficient: the straight line from the previous waypoint
can pass through a school while both endpoints sit safely outside it. Endpoint
only checking is the classic geofence bug, and it is the one worth getting right
in front of people who fly for a living.

Relationship to PX4's own fence, since it is the first question asked:

    PX4's fence stops the AIRCRAFT at a boundary, after it has flown to it, and
    triggers a failsafe. This refuses the COMMAND before it is ever uploaded, so
    the aircraft never departs. Both are wanted. Neither replaces the other, and
    PX4's is authoritative because it survives everything above it failing.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Literal, Optional

FenceType = Literal["inclusion", "exclusion"]


@dataclass(frozen=True)
class Point:
    lat: float
    lon: float


@dataclass(frozen=True)
class Fence:
    name: str
    fence_type: FenceType
    points: tuple[Point, ...]

    def contains(self, p: Point) -> bool:
        """Ray casting. Longitude is x, latitude is y.

        Good to a few metres at the scale a fence covers, which is the accuracy
        the fence itself is surveyed to. Anything needing better wants a
        projected CRS, not a bigger float.
        """
        inside = False
        n = len(self.points)
        for i in range(n):
            a, b = self.points[i], self.points[(i + 1) % n]
            if (a.lat > p.lat) != (b.lat > p.lat):
                x = (b.lon - a.lon) * (p.lat - a.lat) / (b.lat - a.lat) + a.lon
                if p.lon < x:
                    inside = not inside
        return inside

    def crossed_by(self, a: Point, b: Point) -> bool:
        """Does the leg a->b intersect any edge of this polygon?

        The check endpoint containment misses: both ends outside, the straight
        line through the middle.
        """
        n = len(self.points)
        for i in range(n):
            c, d = self.points[i], self.points[(i + 1) % n]
            if _segments_cross(a, b, c, d):
                return True
        return False


def _orient(p: Point, q: Point, r: Point) -> int:
    v = (q.lat - p.lat) * (r.lon - q.lon) - (q.lon - p.lon) * (r.lat - q.lat)
    if abs(v) < 1e-15:
        return 0
    return 1 if v > 0 else -1


def _segments_cross(p1: Point, p2: Point, p3: Point, p4: Point) -> bool:
    o1, o2 = _orient(p1, p2, p3), _orient(p1, p2, p4)
    o3, o4 = _orient(p3, p4, p1), _orient(p3, p4, p2)
    return o1 != o2 and o3 != o4


@dataclass(frozen=True)
class FenceVerdict:
    allowed: bool
    fence: str = ""
    reason: str = ""


class Geofence:
    """The surveyed operating area: one inclusion boundary, N exclusions."""

    def __init__(self, fences: Iterable[Fence]):
        self.fences = tuple(fences)

    @property
    def inclusions(self) -> tuple[Fence, ...]:
        return tuple(f for f in self.fences if f.fence_type == "inclusion")

    @property
    def exclusions(self) -> tuple[Fence, ...]:
        return tuple(f for f in self.fences if f.fence_type == "exclusion")

    def check(self, target: Point, previous: Optional[Point] = None) -> FenceVerdict:
        """Refuse a waypoint outside the boundary, inside an exclusion, or whose
        leg crosses one."""
        for f in self.inclusions:
            if not f.contains(target):
                return FenceVerdict(False, f.name,
                                    f"waypoint is outside the '{f.name}' boundary")

        for f in self.exclusions:
            if f.contains(target):
                return FenceVerdict(False, f.name,
                                    f"waypoint is inside exclusion zone '{f.name}'")

        if previous is not None:
            for f in self.exclusions:
                if f.crossed_by(previous, target):
                    return FenceVerdict(False, f.name,
                                        f"leg crosses exclusion zone '{f.name}' "
                                        f"even though both waypoints are outside it")
        return FenceVerdict(True)

    def to_mavsdk(self):
        """The same fences as MAVSDK Polygons, for upload to PX4.

        The point of returning these: what Shield checks and what the aircraft
        enforces come from ONE definition. Two hand-maintained copies of a
        boundary is how they drift.
        """
        from mavsdk.geofence import (Polygon, Point as MavPoint,
                                     FenceType as MavFenceType, GeofenceData)

        polygons = [
            Polygon(
                [MavPoint(p.lat, p.lon) for p in f.points],
                MavFenceType.INCLUSION if f.fence_type == "inclusion"
                else MavFenceType.EXCLUSION,
            )
            for f in self.fences
        ]
        # upload_geofence takes a GeofenceData, not a bare list. Circles are a
        # separate primitive; this site is polygons only.
        return GeofenceData(polygons, [])


# ── building a site around a home position ─────────────────────────────────
# A real fence is surveyed once and stored in absolute coordinates. SITL starts
# wherever it starts, so the demo derives an equivalent site from the live home
# position. That difference is worth saying out loud rather than implying these
# numbers came off a survey.

def _offset(home: Point, north_m: float, east_m: float) -> Point:
    lat = home.lat + north_m / 111_111.0
    lon = home.lon + east_m / (111_111.0 * math.cos(math.radians(home.lat)))
    return Point(lat, lon)


def _rect(home: Point, n0: float, e0: float, n1: float, e1: float) -> tuple[Point, ...]:
    return (_offset(home, n0, e0), _offset(home, n0, e1),
            _offset(home, n1, e1), _offset(home, n1, e0))


def substation_site(home: Point) -> Geofence:
    """A plausible substation site: assets east, exclusions west and far east.

    The layout is deliberate in two ways.

    The routine inspection route stays clear of every exclusion, because a real
    site is surveyed so that the work can actually be done. A geofence that
    refuses the sortie it was drawn around is a misconfigured geofence, and an
    operator would rightly say the planner should route around an obstacle
    rather than give up. The first version of this site put the school between
    two legitimate assets and blocked the inspection, which demonstrated nothing
    except a badly drawn fence.

    The injected diversion, by contrast, is chosen the way an attacker would
    choose it: the destination itself sits in open ground, outside every fence,
    so a containment check on the endpoint passes. Only the LEG from the last
    legitimate asset crosses the school. That is the case endpoint-only
    geofencing misses, and it is the reason this checks legs.
    """
    return Geofence([
        Fence("site-boundary",  "inclusion", _rect(home, -100, -200, 300, 200)),
        Fence("school-grounds", "exclusion", _rect(home, 100, -120, 170, -40)),
        Fence("public-road",    "exclusion", _rect(home, -80, 150, 280, 180)),
        Fence("control-room",   "exclusion", _rect(home, 20, -80, 50, -50)),
    ])
