import { createClient } from "npm:@supabase/supabase-js@2";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});

Deno.serve(async (req) => {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const { userId, format } = await req.json();

  const { data: notes, error } = await admin
    .from("notes")
    .select("id, title, body, created_at, notebooks(title)")
    .eq("owner_id", userId)
    .order("created_at");
  if (error) return new Response("Export failed", { status: 500 });

  if (format === "markdown") {
    const md = notes.map((n) => `# ${n.title}\n\n${n.body ?? ""}`).join("\n\n---\n\n");
    return new Response(md, { headers: { "content-type": "text/markdown; charset=utf-8" } });
  }
  return Response.json(notes);
});
