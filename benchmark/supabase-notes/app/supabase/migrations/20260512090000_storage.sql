insert into storage.buckets (id, name, public)
values
  ('avatars', 'avatars', true),
  ('attachments', 'attachments', false);

create policy "avatars: owner uploads" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "avatars: owner replaces" on storage.objects
  for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "attachments: read" on storage.objects
  for select to authenticated
  using (bucket_id = 'attachments');

create policy "attachments: upload" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'attachments');
