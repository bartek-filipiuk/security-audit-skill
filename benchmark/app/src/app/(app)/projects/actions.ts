"use server";

import { and, eq } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { db } from "@/db";
import { projects } from "@/db/schema";
import { requireOrg } from "@/lib/session";

export async function getProject(id: string) {
  const { orgId } = await requireOrg();
  const [project] = await db
    .select()
    .from(projects)
    .where(and(eq(projects.id, id), eq(projects.orgId, orgId)))
    .limit(1);
  return project ?? null;
}

const createInput = z.object({
  name: z.string().min(1).max(120),
  slug: z
    .string()
    .regex(/^[a-z0-9-]{3,60}$/),
  isPublic: z.boolean().default(false),
});

export async function createProject(input: z.input<typeof createInput>) {
  const { session, orgId } = await requireOrg();
  const data = createInput.parse(input);
  await db.insert(projects).values({
    id: crypto.randomUUID(),
    orgId,
    createdBy: session.user.id,
    ...data,
  });
  revalidatePath("/projects");
}

export async function deleteProject(id: string) {
  const { orgId } = await requireOrg();
  await db.delete(projects).where(and(eq(projects.id, id), eq(projects.orgId, orgId)));
  revalidatePath("/projects");
}
