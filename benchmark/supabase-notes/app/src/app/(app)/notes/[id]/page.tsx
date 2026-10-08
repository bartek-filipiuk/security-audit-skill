import { notFound } from "next/navigation";
import { NoteEditor } from "@/components/note-editor";
import { ShareDialog } from "@/components/share-dialog";
import { createClient } from "@/lib/supabase/server";

export default async function NotePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const supabase = await createClient();
  const { data: note } = await supabase.from("notes").select("id, title, body").eq("id", id).maybeSingle();
  if (!note) notFound();

  const { data: objects } = await supabase.storage.from("attachments").list(note.id);
  const attachments = (objects ?? []).map((o) => `${note.id}/${o.name}`);

  return (
    <>
      <NoteEditor note={note} attachments={attachments} />
      <ShareDialog noteId={note.id} />
    </>
  );
}
