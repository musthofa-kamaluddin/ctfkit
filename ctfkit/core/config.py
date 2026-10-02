"""
ctfkit.core.config
Configuration manager with dynamic flag format resolution, TOML loading, and env overrides.
"""

from __future__ import annotations
import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

try:
    import tomllib  # Python 3.11+ standard library
except ImportError:
    try:
        import toml as tomllib  # fallback
    except ImportError:
        tomllib = None  # type: ignore


@dataclass
class CompetitionConfig:
    name: str = "CTF Competition"
    flag_prefix: str = "HackToday26{"
    flag_suffix: str = "}"
    flag_regex: str = r"HackToday26\{[a-zA-Z0-9_\-\+\!@#\$\%]+?\}"
    case_sensitive: bool = True


@dataclass
class CryptoConfig:
    max_recursive_depth: int = 8
    beam_width: int = 5
    entropy_threshold_high: float = 7.5
    entropy_threshold_low: float = 3.5
    quadgram_threshold: float = -15.0
    timeout_seconds: int = 30
    max_workers: int = field(default_factory=lambda: max(1, os.cpu_count() or 1))


@dataclass
class KnownPlaintextConfig:
    default_prefix: str = "HackToday26{"
    default_suffix: str = "}"


@dataclass
class Config:
    competition: CompetitionConfig = field(default_factory=CompetitionConfig)
    crypto: CryptoConfig = field(default_factory=CryptoConfig)
    known_plaintext: KnownPlaintextConfig = field(default_factory=KnownPlaintextConfig)
    config_file_path: Optional[Path] = None

    @classmethod
    def load(cls, custom_path: Optional[Path | str] = None) -> Config:
        """
        Loads configuration with priority:
        1. Custom path if provided
        2. ./.ctfkit.toml in current working directory
        3. ~/.config/ctfkit/config.toml
        4. Environment variables
        """
        cfg = cls()
        loaded_dict: Dict[str, Any] = {}

        candidate_paths = []
        if custom_path:
            candidate_paths.append(Path(custom_path))
        candidate_paths.extend([
            Path.cwd() / ".ctfkit.toml",
            Path.cwd().parent / ".ctfkit.toml",
            Path.home() / ".config" / "ctfkit" / "config.toml",
        ])

        target_file = None
        for p in candidate_paths:
            if p.is_file():
                target_file = p
                break

        if target_file and tomllib:
            try:
                with open(target_file, "rb" if hasattr(tomllib, "load") else "r") as f:
                    loaded_dict = tomllib.load(f)
                cfg.config_file_path = target_file
            except Exception:
                pass

        # Apply TOML dictionary values
        if "competition" in loaded_dict:
            comp = loaded_dict["competition"]
            cfg.competition.name = comp.get("name", cfg.competition.name)
            cfg.competition.flag_prefix = comp.get("flag_prefix", cfg.competition.flag_prefix)
            cfg.competition.flag_suffix = comp.get("flag_suffix", cfg.competition.flag_suffix)
            cfg.competition.flag_regex = comp.get("flag_regex", cfg.competition.flag_regex)
            cfg.competition.case_sensitive = comp.get("case_sensitive", cfg.competition.case_sensitive)

        if "crypto" in loaded_dict:
            cry = loaded_dict["crypto"]
            cfg.crypto.max_recursive_depth = cry.get("max_recursive_depth", cfg.crypto.max_recursive_depth)
            cfg.crypto.beam_width = cry.get("beam_width", cfg.crypto.beam_width)
            cfg.crypto.entropy_threshold_high = cry.get("entropy_threshold_high", cfg.crypto.entropy_threshold_high)
            cfg.crypto.entropy_threshold_low = cry.get("entropy_threshold_low", cfg.crypto.entropy_threshold_low)
            cfg.crypto.quadgram_threshold = cry.get("quadgram_threshold", cfg.crypto.quadgram_threshold)
            cfg.crypto.timeout_seconds = cry.get("timeout_seconds", cfg.crypto.timeout_seconds)

        if "known_plaintext" in loaded_dict:
            kp = loaded_dict["known_plaintext"]
            cfg.known_plaintext.default_prefix = kp.get("default_prefix", cfg.known_plaintext.default_prefix)
            cfg.known_plaintext.default_suffix = kp.get("default_suffix", cfg.known_plaintext.default_suffix)

        # Environment variable overrides
        env_prefix = os.environ.get("CTFKIT_FLAG_PREFIX")
        if env_prefix:
            cfg.competition.flag_prefix = env_prefix
            cfg.known_plaintext.default_prefix = env_prefix

        env_suffix = os.environ.get("CTFKIT_FLAG_SUFFIX")
        if env_suffix:
            cfg.competition.flag_suffix = env_suffix
            cfg.known_plaintext.default_suffix = env_suffix

        env_regex = os.environ.get("CTFKIT_FLAG_REGEX")
        if env_regex:
            cfg.competition.flag_regex = env_regex

        return cfg

    def set_flag_prefix(self, prefix: str) -> None:
        """Dynamically reconfigures flag prefix and rebuilds default regex if needed."""
        self.competition.flag_prefix = prefix
        self.known_plaintext.default_prefix = prefix
        # Automatically update regex pattern prefix if using standard syntax
        escaped_prefix = prefix.replace("{", r"\{").replace("}", r"\}")
        escaped_suffix = self.competition.flag_suffix.replace("{", r"\{").replace("}", r"\}")
        self.competition.flag_regex = f"{escaped_prefix}[a-zA-Z0-9_\\-\\+\\!@#\\$\\%]+?{escaped_suffix}"


# Global default configuration instance
_DEFAULT_CONFIG: Optional[Config] = None


def get_config() -> Config:
    global _DEFAULT_CONFIG
    if _DEFAULT_CONFIG is None:
        _DEFAULT_CONFIG = Config.load()
    return _DEFAULT_CONFIG


def set_config(cfg: Config) -> None:
    global _DEFAULT_CONFIG
    _DEFAULT_CONFIG = cfg
