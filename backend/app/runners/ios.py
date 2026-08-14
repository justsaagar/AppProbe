from app.analyzers.ipa import IOS_DYNAMIC_UNAVAILABLE
from app.runners.base import RuntimeRunner, RuntimeStatus


class IosRuntimeRunner(RuntimeRunner):
    name = "ios-device"

    async def available(self) -> RuntimeStatus:
        return RuntimeStatus(
            executed=False,
            reason=IOS_DYNAMIC_UNAVAILABLE,
            details={"platform": "ios", "requires": "macos-device-environment"},
        )
