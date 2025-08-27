from typing import Optional

def score_prediction(pick: Optional[str], margin: int, home_score: int, away_score: int) -> int:
    """
    מחזיר ניקוד לפי הכללים שב-SETTLE.
    pick: "home"/"away"/None
    margin: 0=disabled, >=1 פעילות
    """
    if home_score == away_score:
        raise ValueError("Invalid draw for basketball final score")

    winner = "home" if home_score > away_score else "away"
    real_margin = abs(home_score - away_score)

    if pick is None or margin == 0:
        return 0
    if pick != winner:
        return -2

    dist = abs(real_margin - margin)
    if dist == 0:
        return 8
    if dist == 1:
        return 6
    if dist == 2:
        return 5
    if dist == 3:
        return 4
    return 3