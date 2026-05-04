-- Demo / local: surface ~2500 Elo-style ratings on the leaderboard.
-- Analytics reads live values from auth; usernames match V5 test users.
UPDATE users u
SET rating    = d.rating,
    updated_at = CURRENT_TIMESTAMP
FROM (VALUES ('alice123', 2540),
             ('bob456', 2525),
             ('charlie789', 2510),
             ('david321', 2498),
             ('eve654', 2485),
             ('frank987', 2533),
             ('grace111', 2507),
             ('heidi222', 2472),
             ('ivan333', 2560),
             ('judy444', 2455)) AS d(username, rating)
WHERE u.username = d.username;
