"use server";

import { eq } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { db } from "@/db";
import { user } from "@/db/schema";
import { requireUser } from "@/lib/session";

export async function updateNotifications(formData: FormData) {
  const session = await requireUser();
  const emailDigest = formData.get("emailDigest") === "on";
  await db.update(user).set({ emailDigest, updatedAt: new Date() }).where(eq(user.id, session.user.id));
  revalidatePath("/settings/notifications");
}
