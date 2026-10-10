"use server";

import { and, eq, inArray } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { db } from "@/db";
import { customers, invoices, member, smsMessages } from "@/db/schema";
import { requireOrg } from "@/lib/session";

// Erasure request from one of the organization's customers. Invoices are kept for bookkeeping,
// so the customer is anonymized in place and every copy of their contact details is cleared with it.
export async function eraseCustomer(customerId: string) {
  const { session, orgId } = await requireOrg();
  const [admin] = await db
    .select({ role: member.role })
    .from(member)
    .where(and(eq(member.organizationId, orgId), eq(member.userId, session.user.id), inArray(member.role, ["owner", "admin"])))
    .limit(1);
  if (!admin) return { error: "forbidden" };

  const erased = await db.transaction(async (tx) => {
    const [row] = await tx
      .update(customers)
      .set({ name: "Erased customer", email: `erased-${customerId}@erased.invalid`, phone: null, taxId: null })
      .where(and(eq(customers.id, customerId), eq(customers.orgId, orgId)))
      .returning({ id: customers.id });
    if (!row) return false;
    const theirInvoices = tx
      .select({ id: invoices.id })
      .from(invoices)
      .where(and(eq(invoices.customerId, customerId), eq(invoices.orgId, orgId)));
    await tx
      .update(smsMessages)
      .set({ to: "erased" })
      .where(and(eq(smsMessages.orgId, orgId), inArray(smsMessages.invoiceId, theirInvoices)));
    await tx
      .update(invoices)
      .set({ notes: null })
      .where(and(eq(invoices.customerId, customerId), eq(invoices.orgId, orgId)));
    return true;
  });
  if (!erased) return { error: "not_found" };
  revalidatePath("/invoices");
  return { ok: true };
}
