create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text not null unique,
  display_name text,
  avatar_path text,
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "profiles: owner reads" on public.profiles
  for select to authenticated
  using (id = (select auth.uid()));

create policy "profiles: owner updates" on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

revoke update on public.profiles from anon, authenticated;
grant update (display_name, avatar_path) on public.profiles to authenticated;

create function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, email)
  values (new.id, lower(new.email));
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

create table public.plans (
  id text primary key,
  name text not null,
  monthly_price_cents integer not null,
  note_limit integer not null
);

alter table public.plans enable row level security;

create policy "plans: public catalogue" on public.plans
  for select to anon, authenticated
  using (true);

create table public.subscriptions (
  user_id uuid primary key references auth.users (id) on delete cascade,
  plan_id text not null references public.plans (id),
  status text not null,
  current_period_end timestamptz
);

alter table public.subscriptions enable row level security;

create policy "subscriptions: owner reads" on public.subscriptions
  for select to authenticated
  using (user_id = (select auth.uid()));

create table public.notebooks (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  created_at timestamptz not null default now()
);

alter table public.notebooks enable row level security;

create policy "notebooks: owner reads" on public.notebooks
  for select to authenticated
  using (owner_id = (select auth.uid()));

create policy "notebooks: owner creates" on public.notebooks
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

create policy "notebooks: members rename" on public.notebooks
  for update to authenticated
  using (auth.role() = 'authenticated');

create policy "notebooks: owner deletes" on public.notebooks
  for delete to authenticated
  using (owner_id = (select auth.uid()));

create table public.notes (
  id uuid primary key default gen_random_uuid(),
  notebook_id uuid not null references public.notebooks (id) on delete cascade,
  owner_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.notes enable row level security;

create policy "notes: readable" on public.notes
  for select to authenticated
  using (true);

create policy "notes: owner creates" on public.notes
  for insert to authenticated
  with check (owner_id = (select auth.uid()));

create policy "notes: owner edits" on public.notes
  for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

create policy "notes: owner deletes" on public.notes
  for delete to authenticated
  using (owner_id = (select auth.uid()));

create table public.note_shares (
  note_id uuid not null references public.notes (id) on delete cascade,
  shared_with uuid not null references auth.users (id) on delete cascade,
  shared_with_email text not null,
  can_edit boolean not null default false,
  created_at timestamptz not null default now(),
  primary key (note_id, shared_with)
);

create table public.inbound_addresses (
  token text primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  notebook_id uuid not null references public.notebooks (id) on delete cascade
);

alter table public.inbound_addresses enable row level security;

create policy "inbound addresses: owner reads" on public.inbound_addresses
  for select to authenticated
  using (user_id = (select auth.uid()));
