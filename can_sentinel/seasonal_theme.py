"""Subtle calendar-season palettes for the Streamlit dashboard."""
from __future__ import annotations

_SEASON_COLORS: dict[str, tuple[str, str]] = {
    "winter": ("rgba(113, 164, 205, 0.16)", "rgba(182, 195, 224, 0.15)"),
    "spring": ("rgba(111, 176, 133, 0.15)", "rgba(231, 164, 173, 0.13)"),
    "summer": ("rgba(245, 190, 91, 0.15)", "rgba(112, 181, 213, 0.13)"),
    "autumn": ("rgba(207, 117, 65, 0.15)", "rgba(227, 181, 116, 0.14)"),
}


def season_for_month(month: int) -> str:
    """Return the Northern Hemisphere temperate season for month 1 through 12."""
    if isinstance(month, bool) or not isinstance(month, int) or not 1 <= month <= 12:
        raise ValueError("month must be an integer from 1 through 12")
    if month in (12, 1, 2):
        return "winter"
    if month in (3, 4, 5):
        return "spring"
    if month in (6, 7, 8):
        return "summer"
    return "autumn"


def seasonal_background_css(season: str) -> str:
    """Return a low-opacity background treatment that preserves text contrast."""
    normalized = season.lower()
    if normalized not in _SEASON_COLORS:
        raise ValueError(f"unknown season: {season!r}")
    first, second = _SEASON_COLORS[normalized]
    return f"""<style>
    .stApp {{
      background-color: var(--background-color, #ffffff);
      background-image:
        radial-gradient(ellipse at 7% 2%, {first} 0%, transparent 38%),
        radial-gradient(ellipse at 96% 20%, {second} 0%, transparent 34%);
      background-attachment: fixed;
    }}
    </style>"""
