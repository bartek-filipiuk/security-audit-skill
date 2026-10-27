# Notes

Personal notes with notebooks, sharing and attachments, plus shared whiteboards
for the mobile companion app.

## Stack

Next.js 16 (App Router) on Supabase: Postgres with Row Level Security, Supabase
Auth (magic links), Storage for attachments and avatars, and two Edge Functions
(note export, inbound email to note). Whiteboards live in Firestore with Firebase
Storage for thumbnails and exports, and Cloud Functions for board management.

## Running locally

    pnpm install
    cp .env.example .env.local
    supabase start
    pnpm db:reset
    pnpm functions:serve   # in a second terminal
    pnpm dev

Firebase: `firebase emulators:start` from this directory (rules in
`firestore.rules` and `storage.rules`, functions in `functions/`).

## Security

- Row Level Security is enabled on every table; users only see their own notes
  and notes shared with them.
- The service role key never leaves the server.
- Attachments are private to the note's owner.
- Edge Functions require a signed-in user, except the inbound email hook, which
  checks an HMAC signature.
- Firestore boards are visible to their owner only.
