"""Base module for reputation check implementations."""

from abc import ABC, abstractmethod


class ReputationCheck(ABC):
    """Abstract base class for reputation check implementations."""

    @abstractmethod
    def name(self) -> str:
        """Return the name of the reputation check source."""

    @abstractmethod
    def run(self, target: str, api_key: str | None = None) -> dict[str, str | int | list | dict]:
        """Run the reputation check.

        Args:
        ----
            target: The target (IP, domain, or CIDR block) to check.
            api_key: The API key for the reputation check source.

        Returns:
        -------
            A dictionary containing the results of the reputation check.

        """
