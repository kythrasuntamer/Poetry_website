create table users (
  id bigserial primary key,
  username text unique not null,
  email text unique not null,
  password_hash text not null,
  created_at timestamptz default now()
);

create table poems (
  id bigserial primary key,
  author_id bigint not null references users(id),
  title text not null,
  body text not null,
  created_at timestamptz default now()
);

create table comments (
  id bigserial primary key,
  poem_id bigint not null references poems(id) on delete cascade,
  author_id bigint not null references users(id),
  body text not null,
  created_at timestamptz default now()
);
