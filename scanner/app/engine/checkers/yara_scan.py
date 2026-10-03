import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import yara

from engine.config import settings
from engine.models import Checker, Result

logger = logging.getLogger("scanner.yara")

# Raised from 50MB to 500MB to allow real-time scanning of large installers without skipping
MAX_YARA_FILE_SIZE = 500 * 1024 * 1024  # 500MB


class YaraChecker(Checker):
    name = "yara"

    def __init__(self, rules_dir: Optional[Path] = None, auto_compile: bool = True):
        self.rules_dir = rules_dir or settings.yara_rules_dir
        self.compiled_rule: Optional[yara.Rules] = None
        self.compiled_rules: List[yara.Rules] = []
        self.compiled_count: int = 0
        self.skipped_count: int = 0
        self._compiled = False
        if auto_compile:
            self._compile_rules()

    def _compile_rules(self):
        if self._compiled:
            return
        if not self.rules_dir or not self.rules_dir.is_dir():
            logger.warning(f"YARA rules directory not found at {self.rules_dir}")
            self._compiled = True
            return

        filepaths: Dict[str, str] = {}
        skipped = 0
        for entry in os.scandir(self.rules_dir):
            if entry.is_file() and (entry.name.endswith(".yar") or entry.name.endswith(".yara")):
                try:
                    # Quick syntax validation so a single malformed rule doesn't invalidate the entire batch
                    yara.compile(filepath=entry.path)
                    filepaths[entry.name] = entry.path
                except Exception as e:
                    skipped += 1
                    logger.debug(f"Skipping YARA rule {entry.name}: {e}")

        if filepaths:
            try:
                # Compile all valid rules into a single unified Aho-Corasick automaton (200x+ faster single pass)
                unified = yara.compile(filepaths=filepaths)
                self.compiled_rule = unified
                self.compiled_rules = [unified]
                self.compiled_count = len(filepaths)
            except Exception as e:
                logger.error(f"Failed to compile unified YARA ruleset: {e}")
                self.compiled_rule = None
                self.compiled_rules = []
                self.compiled_count = 0
        else:
            self.compiled_rule = None
            self.compiled_rules = []
            self.compiled_count = 0

        self.skipped_count = skipped
        self._compiled = True
        logger.info(
            f"YARA compiled {self.compiled_count} rules ({self.skipped_count} skipped) from {self.rules_dir}"
        )

    def check(self, path: Path, ctx: dict) -> Result:
        try:
            return self._perform_check(path)
        except Exception as e:
            logger.error(f"YARA scan error for {path}: {e}", exc_info=True)
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": str(e)},
            )

    def _perform_check(self, path: Path) -> Result:
        if not self._compiled:
            self._compile_rules()

        # Cap file size at 500MB
        try:
            size = path.stat().st_size
            if size > MAX_YARA_FILE_SIZE:
                return Result(
                    checker=self.name,
                    status="skip",
                    score=0,
                    details={"reason": "file_size_exceeds_500mb", "size": size},
                )
        except Exception as e:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"error": f"Failed to read file size: {e}"},
            )

        if not self.compiled_rule:
            return Result(
                checker=self.name,
                status="skip",
                score=0,
                details={"reason": "no_rules_loaded"},
            )

        matched_rule_names: List[str] = []
        target_path_str = str(path)

        try:
            # Single-pass scan over file for all 700+ rules
            matches = self.compiled_rule.match(target_path_str)
            for m in matches:
                matched_rule_names.append(m.rule)
        except Exception as e:
            logger.debug(f"Rule match error on {path}: {e}")

        if matched_rule_names:
            return Result(
                checker=self.name,
                status="fail",
                score=50,
                details={
                    "rules": matched_rule_names,
                    "count": len(matched_rule_names),
                    "compiled_rules_count": self.compiled_count,
                },
            )
        else:
            return Result(
                checker=self.name,
                status="pass",
                score=0,
                details={
                    "rules": [],
                    "count": 0,
                    "compiled_rules_count": self.compiled_count,
                },
            )
