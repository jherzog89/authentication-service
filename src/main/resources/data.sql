INSERT INTO users (username, password, roles, enabled)
VALUES ('jason', '$2a$10$DQoxN0uA.kjXYOR37NTiEuJlvacXmKB/vLXPWswXdDRzsfkLokyIK', 'USER', true)
ON CONFLICT (username) DO NOTHING;