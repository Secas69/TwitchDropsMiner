"""
Hardcoded catalog of games known to have Twitch drops.

The catalog pre-populates the "Game name" dropdowns in the Settings tab,
so games the dynamic drop scan hasn't found yet can still be added to the
priority and exclude lists with a single click.

Sources:
- Active drop campaigns: https://twdrop.de (2026-10-23)
- Campaigns from July-October 2026: Twitch Summer Drop Fest (blog.twitch.tv),
  publisher announcements, DTF and artgaming campaign roundups.

Keep game names exactly as they appear as Twitch category names.
"""

from __future__ import annotations

import re
import unicodedata

CATALOG_VERSION = "2026-10-23"
CATALOG_SOURCE = "https://twdrop.de + web research (July-October 2026)"

KNOWN_DROPS_GAMES: tuple[str, ...] = (
    # --- games with active drop campaigns (twdrop.de, 2026-10-23) ---
    "Abnormality",
    "ACE COMBAT 8: WINGS OF THEVE",
    "Airport Baggage Simulator",
    "Albion Online",
    "Alien: Isolation",
    "ARC Raiders",
    "ARKNIGHTS: ENDFIELD",
    "Black Desert",
    "Blue Protocol: Star Resonance",
    "Brawlhalla",
    "Caliber",
    "Captain's Call",
    "Cash is King!",
    "Castlevania: Belmont's Curse",
    "Coin Pusher Live",
    "Coryphaeus Championships",
    "Crossout",
    "Cyberpunk 2077",
    "Dark and Darker",
    "Dead by Daylight",
    "Delta Force",
    "Disney Dreamlight Valley",
    "Don't Starve Together",
    "Doomsday: Last Survivors",
    "Dragon's Dogma II",
    "ELDEN RING",
    "Embervale.TV",
    "Enshrouded",
    "EVE Online",
    "Evil Pongon Game",
    "Fellowship",
    "Fishing Planet",
    "For Honor",
    "Gray Zone Warfare",
    "HITMAN World of Assassination",
    "Honkai Impact 3rd",
    "Honkai: Star Rail",
    "Infestation: The New Z",
    "Kakele Online - MMORPG",
    "League of Legends",
    "Legend of YMIR",
    "Lenin Street Geek Shop",
    "Lineage II",
    "Lords Mobile",
    "Madden NFL 27",
    "Marbles on Stream",
    "MARVEL Contest of Champions",
    "Marvel Rivals",
    "MARVEL SNAP",
    "MARVEL Strike Force",
    "Mir Korabley",
    "Mobile Dungeon",
    "Modern Warships",
    "My Hero Ultra Rumble",
    "NARAKA: BLADEPOINT",
    "NBA 2K27",
    "Night Crows",
    "Once Human",
    "Out of the Park Baseball 27",
    "Overwatch",
    "Planet Zoo 2",
    "QSMP",
    "Rainbow Six Siege",
    "Ravendawn",
    "RavenQuest",
    "Riders Republic",
    "Rise Online",
    "Scape",
    "Shakes and Fidget",
    "SMITE 2",
    "Sonic Rumble Party",
    "Splinterlands",
    "Star Citizen",
    "Stella Sora",
    "Street Fighter 6",
    "Super Animal Royale",
    "THE FINALS",
    "The Quinfall",
    "The Witcher 3: Wild Hunt",
    "The Witcher 3: Wild Hunt Remastered",
    "UFL",
    "UNO! Mobile",
    "VALORANT",
    "Viking Rise",
    "Warframe",
    "Warhammer 40,000: Space Marine II",
    "Where Winds Meet",
    "Witchspire",
    "Wolvesville",
    "World of Tanks",
    "World of Tanks Console",
    "World of Tanks: HEAT",
    "World of Warcraft",
    "World of Warships",
    "Wuthering Waves",
    "Zenless Zone Zero",
    # --- recent campaigns, currently inactive (July-October 2026) ---
    "AION 2",
    "Anno 117: Pax Romana",
    "Aniimo",
    "Apex Legends",
    "Arena Breakout: Infinite",
    "Assassin's Creed Black Flag Resynced",
    "Avatar Legends: The Fighting Game",
    "Battlefield 6",
    "Control",
    "DEAD OR ALIVE 6 Last Round",
    "Detroit: Become Human",
    "Fortnite",
    "Grand Theft Auto V",
    "Goblin Cleanup",
    "Granblue Fantasy: Relink - Endless Ragnarok",
    "Hunt: Showdown 1896",
    "Infinity Nikki",
    "KILLER INN",
    "NBA 2K26",
    "NTE: Neverness to Everness",
    "Palia",
    "Palworld",
    "Path of Exile",
    "Pokémon Champions",
    "Pokémon GO",
    "Pokémon UNITE",
    "REMATCH",
    "Rocket League",
    "Sea of Thieves",
    "The Seven Deadly Sins: Origin",
    "Soulframe",
    "Tides of Tomorrow",
    "Tom Clancy's The Division 2",
    "The Elder Scrolls Online",
)

_WS_RE = re.compile(r"\s+")


def game_key(name: str) -> str:
    """Case-insensitive comparison key for Twitch category names."""
    text = unicodedata.normalize("NFKC", name)
    text = _WS_RE.sub(" ", text).strip()
    return text.casefold()


# normalized name -> canonical catalog spelling (used for dedup in the GUI)
CANONICAL_NAMES: dict[str, str] = {
    game_key(name): name for name in KNOWN_DROPS_GAMES
}
