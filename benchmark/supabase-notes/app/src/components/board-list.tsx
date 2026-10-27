"use client";

import { onAuthStateChanged } from "firebase/auth";
import { collection, onSnapshot, query, where } from "firebase/firestore";
import { httpsCallable } from "firebase/functions";
import { getDownloadURL, ref, uploadBytes } from "firebase/storage";
import { useEffect, useState } from "react";
import { firebaseAuth, firebaseStorage, firestore, functions } from "@/lib/firebase/client";

type Board = { id: string; title: string };

export function BoardList({ renderPng }: { renderPng: (boardId: string) => Promise<Blob> }) {
  const [boards, setBoards] = useState<Board[]>([]);

  useEffect(() => {
    let stop = () => {};
    const unsubscribe = onAuthStateChanged(firebaseAuth, (user) => {
      stop();
      if (!user) return setBoards([]);
      const q = query(collection(firestore, "boards"), where("ownerId", "==", user.uid));
      stop = onSnapshot(q, (snap) => setBoards(snap.docs.map((d) => ({ id: d.id, title: d.get("title") }))));
    });
    return () => {
      stop();
      unsubscribe();
    };
  }, []);

  async function exportBoard(board: Board) {
    const png = await renderPng(board.id);
    const target = ref(firebaseStorage, `exports/${board.id}-${Date.now()}.png`);
    await uploadBytes(target, png, { contentType: "image/png" });
    return getDownloadURL(target);
  }

  async function remove(board: Board) {
    await httpsCallable(functions, "deleteBoard")({ boardId: board.id });
  }

  return (
    <ul>
      {boards.map((b) => (
        <li key={b.id}>
          {b.title}
          <button onClick={() => remove(b)}>Delete</button>
          <button onClick={async () => navigator.clipboard.writeText(await exportBoard(b))}>Copy export link</button>
        </li>
      ))}
    </ul>
  );
}
