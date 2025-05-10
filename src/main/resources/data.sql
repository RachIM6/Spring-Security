INSERT INTO "role" (id, name) VALUES (1, 'ROLE_USER');
INSERT INTO "role" (id, name) VALUES (2, 'ROLE_ADMIN');

-- Password: admin123
INSERT INTO "user" (id, username, password) VALUES (1, 'admin', '$2a$10$N/zCGMvyFOlBp0B9gCjHK.YvRyYftDa5.YEVs04MWUPtJtWfkJcNS');
-- Password: user123
INSERT INTO "user" (id, username, password) VALUES (2, 'user', '$2a$10$m5i6tXMQwMdkvrQmzWIHUe.zofwCJsGOhLGz0ZzpIkSFPQprD1/Ga');

INSERT INTO "user_roles" (user_id, role_id) VALUES (1, 1);
INSERT INTO "user_roles" (user_id, role_id) VALUES (1, 2);
INSERT INTO "user_roles" (user_id, role_id) VALUES (2, 1);