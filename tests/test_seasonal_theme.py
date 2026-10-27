from __future__ import annotations
import pytest
from can_sentinel.seasonal_theme import seasonal_background_css, season_for_month


@pytest.mark.parametrize(
    ("month", "season"),
    [(1, "winter"), (2, "winter"), (3, "spring"), (5, "spring"),
     (6, "summer"), (8, "summer"), (9, "autumn"), (11, "autumn"), (12, "winter")],
)
def test_season_for_calendar_month(month: int, season: str) -> None:
    assert season_for_month(month) == season


@pytest.mark.parametrize("month", [0, 13, -1, 1.5, True])
def test_invalid_month_is_rejected(month: object) -> None:
    with pytest.raises(ValueError):
        season_for_month(month)  # type: ignore[arg-type]


def test_each_season_has_a_valid_background_palette() -> None:
    palettes = [seasonal_background_css(season) for season in ("winter", "spring", "summer", "autumn")]
    assert all("radial-gradient" in css and "background-color" in css for css in palettes)
    assert len(set(palettes)) == 4
    with pytest.raises(ValueError):
        seasonal_background_css("monsoon")
