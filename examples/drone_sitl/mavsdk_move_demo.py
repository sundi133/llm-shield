"""Move a PX4 SITL drone through MAVSDK.

Run this while `make px4_sitl gz_x500` is already running. It connects to the
PX4 onboard MAVLink port, takes off, moves a few meters north/east, and lands.
"""

from __future__ import annotations

import asyncio

from mavsdk import System


CONNECTION_URL = "udpin://0.0.0.0:14540"
TAKEOFF_ALTITUDE_M = 8.0


async def wait_until_connected(drone: System) -> None:
    print("Connecting to PX4 SITL on", CONNECTION_URL)
    async for state in drone.core.connection_state():
        if state.is_connected:
            print("Connected")
            return


async def wait_until_ready(drone: System) -> None:
    print("Waiting for global position estimate")
    async for health in drone.telemetry.health():
        if health.is_global_position_ok and health.is_home_position_ok:
            print("Position estimate ready")
            return


async def current_position(drone: System):
    async for position in drone.telemetry.position():
        return position


async def main() -> None:
    drone = System()
    await drone.connect(system_address=CONNECTION_URL)

    await wait_until_connected(drone)
    await wait_until_ready(drone)

    print(f"Setting takeoff altitude to {TAKEOFF_ALTITUDE_M}m")
    await drone.action.set_takeoff_altitude(TAKEOFF_ALTITUDE_M)

    print("Arming")
    await drone.action.arm()

    print("Taking off")
    await drone.action.takeoff()
    await asyncio.sleep(10)

    start = await current_position(drone)
    target_lat = start.latitude_deg + 0.00005
    target_lon = start.longitude_deg + 0.00005
    target_alt = start.absolute_altitude_m

    print("Flying a few meters north/east")
    print(f"Target lat={target_lat:.7f}, lon={target_lon:.7f}, alt={target_alt:.1f}m")
    await drone.action.goto_location(target_lat, target_lon, target_alt, 0)
    await asyncio.sleep(12)

    print("Landing")
    await drone.action.land()
    await asyncio.sleep(8)

    print("Done")


if __name__ == "__main__":
    asyncio.run(main())
