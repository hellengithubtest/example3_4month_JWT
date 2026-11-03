
-- Users
insert into users(id, username, password, enabled)
values (3001, 'user1', '$2a$10$L8BTPKYxARZdsv8DRTR7KeH.Q2CwqkpFd0FVKmAY4xwKzrBJ3ILUu', true),
       (3002, 'reader', '$2a$10$L8BTPKYxARZdsv8DRTR7KeH.Q2CwqkpFd0FVKmAY4xwKzrBJ3ILUu', true),
       (3003, 'moderator', '$2a$10$L8BTPKYxARZdsv8DRTR7KeH.Q2CwqkpFd0FVKmAY4xwKzrBJ3ILUu', true);

-- Roles are mapped to ROLE_USER, users:read and users:block in UsersDetailsService.
insert into roles(id, name)
values (1, 'USER'),
       (2, 'READ'),
       (3, 'BLOCK');

-- User-role relations
insert into user_roles(user_id, role_id)
values (3001, 1),
       (3002, 2),
       (3003, 2),
       (3003, 3);
