from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
import datetime as dt

from ..db.models import Prediction, Match
from ..core.interfaces import IPredictionService
from ..core.constants import AppConstants, HTTPStatus, ErrorMessages

class PredictionService(IPredictionService):
    def __init__(self, db: Session):
        self.db = db
    
    def _is_match_locked(self, match: Match) -> bool:
        """Check if match is locked for predictions"""
        if not match or not match.match_date:
            return False
        now = dt.datetime.utcnow()
        lock_time = match.match_date - dt.timedelta(minutes=AppConstants.LOCK_MINUTES)
        return now >= lock_time
    
    def _validate_prediction_data(self, margin: int, pick: Optional[str]) -> None:
        """Validate prediction data"""
        if margin is None or margin < 0:
            raise ValueError("margin must be >= 0")
        
        if margin == 0:
            if pick is not None:
                raise ValueError("Cannot set pick when margin=0. Set margin>=1 first.")
        else:
            if pick is None:
                raise ValueError("pick is required when margin>=1")
    
    def create_prediction(self, user_id: int, match_id: int, pick: Optional[str], margin: int) -> Dict[str, Any]:
        """Create a new prediction"""
        self._validate_prediction_data(margin, pick)
        
        match = self.db.get(Match, match_id)
        if not match:
            raise ValueError(ErrorMessages.MATCH_NOT_FOUND)
        
        if self._is_match_locked(match):
            raise ValueError(ErrorMessages.PREDICTIONS_LOCKED)
        
        # Set effective values
        eff_margin = 0 if margin == 0 else margin
        eff_pick = None if margin == 0 else pick
        
        # Check if prediction already exists
        existing_pred = (
            self.db.query(Prediction)
            .filter(Prediction.match_id == match_id, Prediction.user_id == user_id)
            .one_or_none()
        )
        
        if existing_pred:
            if existing_pred.is_final:
                raise ValueError(ErrorMessages.PREDICTION_ALREADY_SETTLED)
            existing_pred.pick = eff_pick
            existing_pred.margin = eff_margin
            prediction = existing_pred
        else:
            prediction = Prediction(
                match_id=match_id,
                user_id=user_id,
                pick=eff_pick,
                margin=eff_margin,
            )
            self.db.add(prediction)
        
        try:
            self.db.commit()
            self.db.refresh(prediction)
        except IntegrityError:
            self.db.rollback()
            # Retry getting existing prediction
            prediction = (
                self.db.query(Prediction)
                .filter(Prediction.match_id == match_id, Prediction.user_id == user_id)
                .one_or_none()
            )
            if prediction and prediction.is_final:
                raise ValueError(ErrorMessages.PREDICTION_ALREADY_SETTLED)
        
        return {
            "id": prediction.id,
            "match_id": prediction.match_id,
            "user_id": prediction.user_id,
            "pick": prediction.pick,
            "margin": prediction.margin,
            "is_final": prediction.is_final
        }
    
    def update_prediction(self, user_id: int, match_id: int, pick: Optional[str], margin: int) -> Dict[str, Any]:
        """Update an existing prediction"""
        self._validate_prediction_data(margin, pick)
        
        prediction = (
            self.db.query(Prediction)
            .filter(Prediction.match_id == match_id, Prediction.user_id == user_id)
            .one_or_none()
        )
        
        if not prediction:
            raise ValueError(ErrorMessages.PREDICTION_NOT_FOUND)
        
        if prediction.user_id != user_id:
            raise ValueError(ErrorMessages.OWN_PREDICTIONS_ONLY)
        
        match = self.db.get(Match, match_id)
        if self._is_match_locked(match):
            raise ValueError(ErrorMessages.PREDICTIONS_LOCKED)
        
        if prediction.is_final:
            raise ValueError(ErrorMessages.PREDICTION_ALREADY_SETTLED)
        
        # Set effective values
        eff_margin = 0 if margin == 0 else margin
        eff_pick = None if margin == 0 else pick
        
        prediction.pick = eff_pick
        prediction.margin = eff_margin
        
        self.db.commit()
        self.db.refresh(prediction)
        
        return {
            "id": prediction.id,
            "match_id": prediction.match_id,
            "user_id": prediction.user_id,
            "pick": prediction.pick,
            "margin": prediction.margin,
            "is_final": prediction.is_final
        }
    
    def get_prediction(self, user_id: int, match_id: int) -> Optional[Dict[str, Any]]:
        """Get a specific prediction"""
        prediction = (
            self.db.query(Prediction)
            .filter(Prediction.match_id == match_id, Prediction.user_id == user_id)
            .one_or_none()
        )
        
        if not prediction:
            return None
        
        return {
            "id": prediction.id,
            "match_id": prediction.match_id,
            "user_id": prediction.user_id,
            "pick": prediction.pick,
            "margin": prediction.margin,
            "is_final": prediction.is_final,
            "points_awarded": prediction.points_awarded
        }
    
    def get_user_predictions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all predictions for a user"""
        predictions = (
            self.db.query(Prediction)
            .filter(Prediction.user_id == user_id)
            .all()
        )
        
        return [
            {
                "id": pred.id,
                "match_id": pred.match_id,
                "user_id": pred.user_id,
                "pick": pred.pick,
                "margin": pred.margin,
                "is_final": pred.is_final,
                "points_awarded": pred.points_awarded
            }
            for pred in predictions
        ]
    
    def delete_prediction(self, user_id: int, match_id: int) -> bool:
        """Delete a prediction"""
        prediction = (
            self.db.query(Prediction)
            .filter(Prediction.match_id == match_id, Prediction.user_id == user_id)
            .one_or_none()
        )
        
        if not prediction:
            return False
        
        self.db.delete(prediction)
        self.db.commit()
        return True
    
    def settle_predictions(self, match_id: int) -> bool:
        """Settle predictions for a match"""
        match = self.db.get(Match, match_id)
        if not match:
            raise ValueError(ErrorMessages.MATCH_NOT_FOUND)
        
        if not match.home_score or not match.away_score:
            raise ValueError(ErrorMessages.MATCH_NOT_FINISHED)
        
        # Calculate winner
        if match.home_score == match.away_score:
            raise ValueError(ErrorMessages.MATCH_NOT_FINISHED_DRAW)
        
        winner = "home" if match.home_score > match.away_score else "away"
        margin = abs(match.home_score - match.away_score)
        
        # Update predictions
        update_sql = text("""
            UPDATE predictions 
            SET is_final = TRUE,
                points_awarded = CASE 
                    WHEN pick = :winner AND margin = :margin THEN 3
                    WHEN pick = :winner THEN 1
                    ELSE 0
                END
            WHERE match_id = :match_id AND is_final = FALSE
        """)
        
        self.db.execute(update_sql, {
            "winner": winner,
            "margin": margin,
            "match_id": match_id
        })
        
        # Get total predictions count
        total_sql = text("SELECT COUNT(*) FROM predictions WHERE match_id = :match_id AND is_final = TRUE")
        result = self.db.execute(total_sql, {"match_id": match_id})
        total_predictions = result.scalar()
        
        self.db.commit()
        return True 