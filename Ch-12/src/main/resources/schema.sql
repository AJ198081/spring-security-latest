CREATE TABLE IF NOT EXISTS CLIENT
(
    id          serial primary key,
    client_id   varchar(50),
    secret      varchar(50),
    scope       varchar(50),
    auth_method varchar(50),
    grant_type  varchar(50),
    redirect_ui varchar(50)
);

CREATE TABLE IF NOT EXISTS USERS
(
    id          serial primary key,
    username    varchar(50),
    password    varchar(50),
    authorities varchar(100)
);



