"use server";

import { and, eq } from "drizzle-orm";
import { redirect } from "next/navigation";
import { db } from "@/db";
import { member, organization } from "@/db/schema";
import { requireOrg } from "@/lib/session";

// Settings → Danger zone: "Permanently delete this organization and all of its data, including uploaded documents."
export async function deleteOrganization(confirmSlug: string) {
  const { session, orgId } = await requireOrg();
  const [owner] = await db
    .select({ slug: organization.slug })
    .from(member)
    .innerJoin(organization, eq(organization.id, member.organizationId))
    .where(and(eq(member.organizationId, orgId), eq(member.userId, session.user.id), eq(member.role, "owner")))
    .limit(1);
  if (!owner || owner.slug !== confirmSlug) return { error: "forbidden" };

  // Every org-owned table references organization with onDelete: "cascade", documents included.
  await db.delete(organization).where(eq(organization.id, orgId));
  redirect("/onboarding");
}
