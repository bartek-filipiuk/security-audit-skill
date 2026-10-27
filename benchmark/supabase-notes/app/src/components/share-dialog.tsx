"use client";

import { useState } from "react";
import { findUserByEmail } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/client";

export function ShareDialog({ noteId }: { noteId: string }) {
  const [email, setEmail] = useState("");
  const [canEdit, setCanEdit] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  async function share() {
    const person = await findUserByEmail(email);
    if (!person) {
      setStatus("Nobody with that email uses Notes yet.");
      return;
    }
    const { error } = await createClient().rpc("share_note", { p_note_id: noteId, p_email: email, p_can_edit: canEdit });
    setStatus(error ? "Could not share the note." : `Shared with ${person.display_name ?? person.email}.`);
  }

  return (
    <div className="share-dialog">
      <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@company.example" />
      <label>
        <input type="checkbox" checked={canEdit} onChange={(e) => setCanEdit(e.target.checked)} /> Can edit
      </label>
      <button onClick={share}>Share</button>
      {status && <p>{status}</p>}
    </div>
  );
}
