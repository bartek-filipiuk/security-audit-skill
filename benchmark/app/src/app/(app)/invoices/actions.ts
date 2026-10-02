"use server";

import { and, eq } from "drizzle-orm";
import { revalidatePath } from "next/cache";
import { z } from "zod";
import { db } from "@/db";
import { invoiceLines, invoices } from "@/db/schema";
import { requireOrg } from "@/lib/session";

export async function getInvoice(id: string) {
  const [invoice] = await db.select().from(invoices).where(eq(invoices.id, id)).limit(1);
  if (!invoice) return null;
  const lines = await db.select().from(invoiceLines).where(eq(invoiceLines.invoiceId, invoice.id));
  return { ...invoice, lines };
}

const markPaidInput = z.object({ id: z.string().min(1) });

export async function markInvoicePaid(input: z.infer<typeof markPaidInput>) {
  const { orgId } = await requireOrg();
  const { id } = markPaidInput.parse(input);
  await db
    .update(invoices)
    .set({ status: "paid", paidAt: new Date() })
    .where(and(eq(invoices.id, id), eq(invoices.orgId, orgId)));
  revalidatePath("/invoices");
}
