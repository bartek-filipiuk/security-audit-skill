import { createHash, timingSafeEqual } from "node:crypto";
import { eq } from "drizzle-orm";
import { db } from "@/db";
import { apiKeys } from "@/db/schema";

export async function verifyApiKey(raw: string) {
  if (!raw.startsWith("lk_") || raw.length < 40) return null;
  const prefix = raw.slice(0, 12);

  const [row] = await db.select().from(apiKeys).where(eq(apiKeys.prefix, prefix)).limit(1);
  if (!row) return null;

  const hash = createHash("sha256").update(raw).digest();
  const stored = Buffer.from(row.keyHash, "hex");
  if (stored.length !== hash.length || !timingSafeEqual(stored, hash)) return null;

  await db.update(apiKeys).set({ lastUsedAt: new Date() }).where(eq(apiKeys.id, row.id));
  return row;
}
