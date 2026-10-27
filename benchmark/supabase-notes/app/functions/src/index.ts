import { initializeApp } from "firebase-admin/app";
import { FieldValue, getFirestore } from "firebase-admin/firestore";
import { getStorage } from "firebase-admin/storage";
import { HttpsError, onCall } from "firebase-functions/v2/https";

initializeApp();
const db = getFirestore();

export const renameBoard = onCall({ enforceAppCheck: true }, async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in first.");
  const { boardId, title } = request.data as { boardId: string; title: string };
  const ref = db.collection("boards").doc(String(boardId));
  const snap = await ref.get();
  if (!snap.exists || snap.get("ownerId") !== uid) throw new HttpsError("permission-denied", "Not your board.");
  await ref.update({ title: String(title).slice(0, 120), updatedAt: FieldValue.serverTimestamp() });
  return { ok: true };
});

export const deleteBoard = onCall({ enforceAppCheck: true }, async (request) => {
  const { boardId } = request.data as { boardId: string };
  const ref = db.collection("boards").doc(String(boardId));
  await db.recursiveDelete(ref);
  await getStorage().bucket().deleteFiles({ prefix: `boards/${boardId}/` });
  return { ok: true };
});
