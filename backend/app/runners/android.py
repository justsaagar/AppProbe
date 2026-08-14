from app.runners.base import RuntimeRunner, RuntimeStatus

ANDROID_EMULATOR_UNAVAILABLE = "Android Emulator unavailable"


class AndroidEmulatorRunner(RuntimeRunner):
    """Milestone 1 stub. Detects that emulator/ADB integration is not implemented."""

    name = "android-emulator"

    async def available(self) -> RuntimeStatus:
        return RuntimeStatus(
            executed=False,
            reason=ANDROID_EMULATOR_UNAVAILABLE,
            details={
                "adb": "not_checked_in_milestone_1",
                "emulator": "not_implemented",
            },
        )
