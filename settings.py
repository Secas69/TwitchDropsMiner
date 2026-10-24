from __future__ import annotations

from typing import Any, TypedDict, TYPE_CHECKING

from yarl import URL

from utils import json_load, json_save
from constants import SETTINGS_PATH, DEFAULT_LANG, DEFAULT_CLIENT_TYPE, PriorityMode
from drops_catalog import CANONICAL_NAMES, game_key

if TYPE_CHECKING:
    from main import ParsedArgs


class SettingsFile(TypedDict):
    proxy: URL
    language: str
    dark_mode: bool
    exclude: set[str]
    priority: list[str]
    autostart_tray: bool
    connection_quality: int
    tray_notifications: bool
    enable_badges_emotes: bool
    available_drops_check: bool
    priority_mode: PriorityMode
    client_type: str
    campaign_discovery: bool


default_settings: SettingsFile = {
    "proxy": URL(),
    "priority": [],
    "exclude": set(),
    "dark_mode": False,
    "autostart_tray": False,
    "connection_quality": 1,
    "language": DEFAULT_LANG,
    "tray_notifications": True,
    "enable_badges_emotes": False,
    "available_drops_check": True,
    "priority_mode": PriorityMode.PRIORITY_ONLY,
    "client_type": DEFAULT_CLIENT_TYPE,
    "campaign_discovery": True,
}


class Settings:
    # from args
    log: bool
    tray: bool
    dump: bool
    # args properties
    debug_ws: int
    debug_gql: int
    logging_level: int
    # from settings file
    proxy: URL
    language: str
    dark_mode: bool
    exclude: set[str]
    priority: list[str]
    autostart_tray: bool
    connection_quality: int
    tray_notifications: bool
    enable_badges_emotes: bool
    available_drops_check: bool
    priority_mode: PriorityMode
    client_type: str
    campaign_discovery: bool

    PASSTHROUGH = ("_settings", "_args", "_altered")

    def __init__(self, args: ParsedArgs):
        self._settings: SettingsFile = json_load(SETTINGS_PATH, default_settings)
        # canonicalize stored game names against the drops catalog, so old
        # name variants (e.g. different capitalization) keep matching the
        # official Twitch category names; dedupe while preserving order
        priority: list[str] = []
        seen: set[str] = set()
        for name in self._settings["priority"]:
            if not isinstance(name, str):
                continue
            canonical: str = CANONICAL_NAMES.get(game_key(name), name)
            key: str = game_key(canonical)
            if key not in seen:
                seen.add(key)
                priority.append(canonical)
        self._settings["priority"] = priority
        self._settings["exclude"] = {
            CANONICAL_NAMES.get(game_key(name), name) if isinstance(name, str) else name
            for name in self._settings["exclude"]
        }
        # the miner currently only works with "Priority list only",
        # so any older stored value is normalized away on load
        self._settings["priority_mode"] = PriorityMode.PRIORITY_ONLY
        self._args: ParsedArgs = args
        self._altered: bool = False

    # default logic of reading settings is to check args first, then the settings file
    def __getattr__(self, name: str, /) -> Any:
        if name in self.PASSTHROUGH:
            # passthrough
            return getattr(super(), name)
        elif hasattr(self._args, name):
            return getattr(self._args, name)
        elif name in self._settings:
            return self._settings[name]  # type: ignore[literal-required]
        return getattr(super(), name)

    def __setattr__(self, name: str, value: Any, /) -> None:
        if name in self.PASSTHROUGH:
            # passthrough
            return super().__setattr__(name, value)
        if name == "priority_mode":
            # the miner currently only works with "Priority list only",
            # so no other value can ever reach the settings file
            value = PriorityMode.PRIORITY_ONLY
        if name in self._settings:
            self._settings[name] = value  # type: ignore[literal-required]
            self._altered = True
            return
        raise TypeError(f"{name} is missing a custom setter")

    def __delattr__(self, name: str, /) -> None:
        raise RuntimeError("settings can't be deleted")

    def alter(self) -> None:
        self._altered = True

    def save(self, *, force: bool = False) -> None:
        if self._altered or force:
            json_save(SETTINGS_PATH, self._settings, sort=True)
