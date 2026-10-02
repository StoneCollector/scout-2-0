from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, Literal
from pydantic import BaseModel, Field

Verdict = Literal["pass", "review", "block"]
CheckStatus = Literal["pass", "warn", "fail", "skip"]


class Result(BaseModel):
    checker: str
    status: CheckStatus
    score: int
    details: Dict[str, Any] = Field(default_factory=dict)


class Checker(ABC):
    name: str

    @abstractmethod
    def check(self, path: Path, ctx: dict) -> Result:
        """Run the check on path and return a Result.
        Checkers must catch their own exceptions and return status='skip' with error details.
        """
        pass
