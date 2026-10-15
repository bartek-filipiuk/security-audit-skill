"use server";

import { and, count, eq, sql } from "drizzle-orm";
import { db } from "@/db";
import { customers, invoices, smsMessages } from "@/db/schema";
import { formatMoney } from "@/lib/format";
import { requireOrg } from "@/lib/session";
import { sendSms } from "@/lib/sms";

const ORG_DAILY_SMS_LIMIT = 50;

export async function sendSmsReminder(invoiceId: string) {
  const { orgId } = await requireOrg();
  const [invoice] = await db
    .select({ number: invoices.number, amountCents: invoices.amountCents, currency: invoices.currency, phone: customers.phone })
    .from(invoices)
    .innerJoin(customers, eq(customers.id, invoices.customerId))
    .where(and(eq(invoices.id, invoiceId), eq(invoices.orgId, orgId)))
    .limit(1);
  if (!invoice?.phone) return { error: "not_found" };

  const sentOn = new Date().toISOString().slice(0, 10);
  const allowed = await db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(hashtext(${orgId}))`);
    const [{ sentToday }] = await tx
      .select({ sentToday: count() })
      .from(smsMessages)
      .where(and(eq(smsMessages.orgId, orgId), eq(smsMessages.sentOn, sentOn)));
    if (sentToday >= ORG_DAILY_SMS_LIMIT) return false;
    const inserted = await tx
      .insert(smsMessages)
      .values({ id: crypto.randomUUID(), orgId, invoiceId, to: invoice.phone!, sentOn })
      .onConflictDoNothing()
      .returning({ id: smsMessages.id });
    return inserted.length > 0;
  });
  if (!allowed) return { error: "limit_reached" };

  await sendSms({
    to: invoice.phone,
    body: `Reminder: invoice ${invoice.number} (${formatMoney(invoice.amountCents, invoice.currency)}) is due.`,
  });
  return { ok: true };
}
