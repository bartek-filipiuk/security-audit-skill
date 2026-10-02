import "server-only";
import { and, count, eq, gte, sum } from "drizzle-orm";
import { unstable_cache } from "next/cache";
import { db } from "@/db";
import { invoices, projects, usageEvents } from "@/db/schema";

export const getOrgStats = unstable_cache(
  async (orgId: string) => {
    const [p] = await db.select({ total: count() }).from(projects).where(eq(projects.orgId, orgId));
    const [open] = await db
      .select({ total: sum(invoices.amountCents) })
      .from(invoices)
      .where(and(eq(invoices.orgId, orgId), eq(invoices.status, "open")));
    return { projects: p.total, openInvoiceCents: Number(open.total ?? 0) };
  },
  ["org-stats"],
  { revalidate: 300, tags: ["org-stats"] },
);

export async function getUsageThisMonth(orgId: string) {
  const since = startOfMonth(new Date());
  const load = unstable_cache(
    async () =>
      db
        .select({ kind: usageEvents.kind, units: sum(usageEvents.units) })
        .from(usageEvents)
        .where(and(eq(usageEvents.orgId, orgId), gte(usageEvents.createdAt, since)))
        .groupBy(usageEvents.kind),
    ["usage-month"],
    { revalidate: 600 },
  );
  return load();
}

function startOfMonth(d: Date) {
  return new Date(d.getFullYear(), d.getMonth(), 1);
}
