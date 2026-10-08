import { createClient } from "@supabase/supabase-js";

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { persistSession: false } },
);

export async function findUserByEmail(email: string) {
  const { data } = await supabaseAdmin
    .from("profiles")
    .select("id, email, display_name")
    .eq("email", email.trim().toLowerCase())
    .maybeSingle();
  return data;
}
