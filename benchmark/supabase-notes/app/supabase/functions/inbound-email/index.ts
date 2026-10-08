import { createClient } from "npm:@supabase/supabase-js@2";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});
const encoder = new TextEncoder();
const MAX_AGE_SECONDS = 300;

async function validSignature(raw: string, timestamp: string | null, signature: string | null) {
  if (!timestamp || !signature || !/^[0-9a-f]{64}$/.test(signature)) return false;
  const sentAt = Number(timestamp);
  if (!Number.isFinite(sentAt) || Math.abs(Date.now() / 1000 - sentAt) > MAX_AGE_SECONDS) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(Deno.env.get("INBOUND_EMAIL_SECRET")!),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  const bytes = Uint8Array.from(signature.match(/.{2}/g)!, (h) => parseInt(h, 16));
  return crypto.subtle.verify("HMAC", key, bytes, encoder.encode(`${timestamp}.${raw}`));
}

Deno.serve(async (req) => {
  const raw = await req.text();
  const ok = await validSignature(raw, req.headers.get("x-inbound-timestamp"), req.headers.get("x-inbound-signature"));
  if (!ok) return new Response("Invalid signature", { status: 401 });

  const mail = JSON.parse(raw);
  const token = String(mail.to ?? "").split("@")[0];
  const { data: inbox } = await admin
    .from("inbound_addresses")
    .select("user_id, notebook_id")
    .eq("token", token)
    .maybeSingle();
  if (!inbox) return new Response("Unknown address", { status: 404 });

  const { error } = await admin.from("notes").insert({
    owner_id: inbox.user_id,
    notebook_id: inbox.notebook_id,
    title: String(mail.subject ?? "Untitled").slice(0, 200),
    body: String(mail.text ?? "").slice(0, 50_000),
  });
  if (error) return new Response("Could not save", { status: 500 });
  return new Response(null, { status: 204 });
});
