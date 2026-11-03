
-- Users
insert into users(id, username, password, enabled)
values (3001, 'user1', '$2a$10$L8BTPKYxARZdsv8DRTR7KeH.Q2CwqkpFd0FVKmAY4xwKzrBJ3ILUu', true),
       (3002, 'user2', '$2a$10$L8BTPKYxARZdsv8DRTR7KeH.Q2CwqkpFd0FVKmAY4xwKzrBJ3ILUu', true),
       (3003, 'admin', '$2a$10$L8BTPKYxARZdsv8DRTR7KeH.Q2CwqkpFd0FVKmAY4xwKzrBJ3ILUu', true);

-- Roles are stored without the ROLE_ prefix. Spring Security adds it in UsersDetailsService.
insert into roles(id, name)
values (1, 'USER'),
       (2, 'ADMIN');

-- User-role relations
insert into user_roles(user_id, role_id)
values (3001, 1),
       (3002, 1),
       (3003, 2);
