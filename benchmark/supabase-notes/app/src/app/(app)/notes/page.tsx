import Link from "next/link";
import { redirect } from "next/navigation";
import { createClient } from "@/lib/supabase/server";

export default async function NotesPage() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  const { data: notes } = await supabase
    .from("notes")
    .select("id, title, updated_at, notebooks(title)")
    .eq("owner_id", user.id)
    .order("updated_at", { ascending: false });

  return (
    <ul>
      {(notes ?? []).map((n) => (
        <li key={n.id}>
          <Link href={`/notes/${n.id}`}>{n.title}</Link>
        </li>
      ))}
    </ul>
  );
}
