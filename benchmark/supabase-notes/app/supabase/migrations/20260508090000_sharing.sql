create function public.share_note(p_note_id uuid, p_email text, p_can_edit boolean default false)
returns void
language plpgsql
security definer
as $$
declare
  v_user uuid;
begin
  select id into v_user from public.profiles where email = lower(p_email);
  if v_user is null then
    raise exception 'no user with that email';
  end if;

  insert into public.note_shares (note_id, shared_with, shared_with_email, can_edit)
  values (p_note_id, v_user, lower(p_email), p_can_edit)
  on conflict (note_id, shared_with) do update set can_edit = excluded.can_edit;
end;
$$;

create function public.notebook_note_counts()
returns table (notebook_id uuid, note_count bigint)
language sql
stable
security definer
set search_path = ''
as $$
  select n.notebook_id, count(*)
  from public.notes n
  where n.owner_id = (select auth.uid())
  group by n.notebook_id;
$$;

revoke execute on function public.notebook_note_counts() from public, anon;
grant execute on function public.notebook_note_counts() to authenticated;
