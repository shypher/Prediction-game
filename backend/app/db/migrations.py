from sqlalchemy import inspect, text

def ensure_match_columns(engine):
    with engine.begin() as conn:
        insp = inspect(conn)
        cols = {c['name'] for c in insp.get_columns('matches')}
        if 'Round' in cols and 'round' not in cols:
            conn.execute(text('ALTER TABLE matches RENAME COLUMN "Round" TO "round"'))
            cols.add('round')
        if 'LeagueId' in cols and 'league_id' not in cols:
            conn.execute(text('ALTER TABLE matches RENAME COLUMN "LeagueId" TO league_id'))
            cols.add('league_id')
        if 'Season' in cols and 'season' not in cols:
            conn.execute(text('ALTER TABLE matches RENAME COLUMN "Season" TO season'))
            cols.add('season')

        # Whitelist of allowed column names and their DDL definitions
        needed = {
            'home_team': 'VARCHAR',
            'away_team': 'VARCHAR',
            'match_date': 'TIMESTAMP',
            'home_score': 'INTEGER',
            'away_score': 'INTEGER',
            'round': '"round" INTEGER',      
            'league_id': 'INTEGER',
            'season': 'INTEGER',
            'external_id': 'VARCHAR',
            'status': "VARCHAR DEFAULT 'scheduled'",
            'league_name': 'VARCHAR',
            'country': 'VARCHAR',
            'timezone': 'VARCHAR',
            'last_update': 'TIMESTAMP',
            'source': 'VARCHAR',
        }
        
        # Whitelist of allowed column names for security
        allowed_columns = {
            'home_team', 'away_team', 'match_date', 'home_score', 'away_score',
            'round', 'league_id', 'season', 'external_id', 'status', 'league_name',
            'country', 'timezone', 'last_update', 'source'
        }
        
        for name, ddl in needed.items():
            if name not in cols:
                # Validate column name against whitelist
                if name not in allowed_columns:
                    raise ValueError(f"Invalid column name: {name}")
                
                if name == 'round':
                    # Special case for quoted column name
                    conn.execute(text('ALTER TABLE matches ADD COLUMN "round" INTEGER'))
                else:
                    # Use string formatting with validated column name
                    # This is safe because we validate against whitelist
                    conn.execute(text(f'ALTER TABLE matches ADD COLUMN {name} {ddl}'))

        try:
            conn.execute(text(
                "CREATE UNIQUE INDEX IF NOT EXISTS ix_matches_external_id ON matches (external_id)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_matches_match_date ON matches (match_date)"
            ))
            conn.execute(text(
                "CREATE INDEX IF NOT EXISTS ix_matches_status ON matches (status)"
            ))
        except Exception:
            pass