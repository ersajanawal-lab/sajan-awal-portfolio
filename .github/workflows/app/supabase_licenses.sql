-- =====================================================================
-- Construction PM App - BETA PRODUCT KEYS (run once in Supabase SQL Editor)
-- The app calls check_license() every time it opens. Only the three
-- functions below are reachable from the app; the tables are private.
-- This is independent of supabase_step1_schema.sql (shared project data).
-- =====================================================================

create table if not exists public.licenses (
  key         text primary key,                       -- stored UPPERCASE, e.g. 3F9A-0C21-7B4E-D815
  holder      text,                                   -- who it was issued to
  plan        text not null default 'beta',
  status      text not null default 'active' check (status in ('active','revoked')),
  expires_at  timestamptz,                            -- null = never expires
  max_devices int  not null default 1,                -- how many devices may use the key
  notes       text,
  created_at  timestamptz not null default now()
);

create table if not exists public.license_devices (
  key         text not null references public.licenses(key) on delete cascade,
  device_id   text not null,
  first_seen  timestamptz not null default now(),
  last_seen   timestamptz not null default now(),
  app_version text,
  primary key (key, device_id)
);

-- Tables are private: RLS on, no policies, no direct grants
alter table public.licenses        enable row level security;
alter table public.license_devices enable row level security;
revoke all on public.licenses        from anon, authenticated;
revoke all on public.license_devices from anon, authenticated;

-- ---------- Called by the app every time it opens ----------------------
create or replace function public.check_license(p_key text, p_device text, p_version text default null)
returns json language plpgsql security definer set search_path = public as $$
declare l public.licenses; n int;
begin
  select * into l from public.licenses where key = upper(trim(p_key));
  if not found                 then return json_build_object('valid', false, 'reason', 'invalid'); end if;
  if l.status <> 'active'      then return json_build_object('valid', false, 'reason', 'revoked'); end if;
  if l.expires_at is not null and l.expires_at < now()
                               then return json_build_object('valid', false, 'reason', 'expired'); end if;

  if exists (select 1 from public.license_devices where key = l.key and device_id = p_device) then
    update public.license_devices set last_seen = now(), app_version = p_version
     where key = l.key and device_id = p_device;
  else
    select count(*) into n from public.license_devices where key = l.key;
    if n >= l.max_devices then return json_build_object('valid', false, 'reason', 'device_limit'); end if;
    insert into public.license_devices(key, device_id, app_version) values (l.key, p_device, p_version);
  end if;

  return json_build_object('valid', true, 'holder', l.holder, 'plan', l.plan, 'expires_at', l.expires_at);
end $$;

-- ---------- Lets a user free their seat (Settings -> Deactivate this device)
create or replace function public.release_device(p_key text, p_device text)
returns json language plpgsql security definer set search_path = public as $$
begin
  delete from public.license_devices where key = upper(trim(p_key)) and device_id = p_device;
  return json_build_object('ok', true);
end $$;

revoke all on function public.check_license(text,text,text)  from public;
revoke all on function public.release_device(text,text)      from public;
grant execute on function public.check_license(text,text,text) to anon, authenticated;
grant execute on function public.release_device(text,text)     to anon, authenticated;

-- ---------- YOU run this to issue a key (SQL editor only, not callable from the app)
-- select public.new_license('Acme Builders Pty Ltd', 90, 2);   -- holder, days valid, max devices
create or replace function public.new_license(p_holder text, p_days int default 90, p_devices int default 1)
returns text language plpgsql security definer set search_path = public as $$
declare u text := upper(replace(gen_random_uuid()::text, '-', '')); k text;
begin
  k := substr(u,1,4) || '-' || substr(u,5,4) || '-' || substr(u,9,4) || '-' || substr(u,13,4);
  insert into public.licenses(key, holder, expires_at, max_devices)
  values (k, p_holder, case when p_days is null then null else now() + make_interval(days => p_days) end, p_devices);
  return k;
end $$;
revoke all on function public.new_license(text,int,int) from public, anon, authenticated;

-- ---------- Everyday management (run in the SQL editor) -----------------
-- Revoke a key:            update public.licenses set status = 'revoked' where key = 'XXXX-XXXX-XXXX-XXXX';
-- Extend by 30 days:       update public.licenses set expires_at = coalesce(expires_at, now()) + interval '30 days' where key = '...';
-- Allow a 2nd device:      update public.licenses set max_devices = 2 where key = '...';
-- See who is using what:   select l.key, l.holder, l.status, l.expires_at, d.device_id, d.last_seen, d.app_version
--                          from public.licenses l left join public.license_devices d using (key) order by l.created_at desc;
-- Free a stuck device:     delete from public.license_devices where key = '...';
