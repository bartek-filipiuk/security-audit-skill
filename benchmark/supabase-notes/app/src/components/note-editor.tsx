"use client";

import { useState } from "react";
import { createClient } from "@/lib/supabase/client";

type Note = { id: string; title: string; body: string | null };

export function NoteEditor({ note, attachments }: { note: Note; attachments: string[] }) {
  const supabase = createClient();
  const [title, setTitle] = useState(note.title);
  const [body, setBody] = useState(note.body ?? "");
  const [files, setFiles] = useState(attachments);

  async function save() {
    await supabase.from("notes").update({ title, body, updated_at: new Date().toISOString() }).eq("id", note.id);
  }

  async function attach(file: File) {
    const path = `${note.id}/${crypto.randomUUID()}-${file.name}`;
    const { error } = await supabase.storage.from("attachments").upload(path, file, { contentType: file.type });
    if (!error) setFiles((f) => [...f, path]);
  }

  async function open(path: string) {
    const { data } = await supabase.storage.from("attachments").createSignedUrl(path, 60);
    if (data) window.open(data.signedUrl, "_blank", "noopener");
  }

  return (
    <div>
      <input value={title} onChange={(e) => setTitle(e.target.value)} />
      <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={20} />
      <button onClick={save}>Save</button>
      <input type="file" onChange={(e) => e.target.files?.[0] && attach(e.target.files[0])} />
      <ul>
        {files.map((p) => (
          <li key={p}>
            <button onClick={() => open(p)}>{p.split("/").pop()}</button>
          </li>
        ))}
      </ul>
    </div>
  );
}
