"""Base source class."""
from abc import ABC, abstractmethod
from sentinelscout.models import IOCResult, Source


class BaseSource(ABC):
    name: str = "base"
    source: Source = Source.VIRUSTOTAL  # placeholder, override in subclass

    @abstractmethod
    async def query(self, indicator: str) -> IOCResult:
        raise NotImplementedError

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"