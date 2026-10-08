"use server";

import { anthropic } from "@ai-sdk/anthropic";
import { generateText } from "ai";
import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { customers, invoices } from "@/db/schema";
import { sendEmail } from "@/lib/email";
import { formatMoney } from "@/lib/format";
import { requireOrg } from "@/lib/session";

const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

export async function sendAiReminder(invoiceId: string) {
  const { orgId } = await requireOrg();
  const [invoice] = await db
    .select({ number: invoices.number, amountCents: invoices.amountCents, currency: invoices.currency, notes: invoices.notes, to: customers.email })
    .from(invoices)
    .innerJoin(customers, eq(customers.id, invoices.customerId))
    .where(and(eq(invoices.id, invoiceId), eq(invoices.orgId, orgId)))
    .limit(1);
  if (!invoice?.to) return { error: "not_found" };

  const { text } = await generateText({
    model: anthropic("claude-haiku-4-5"),
    maxOutputTokens: 300,
    prompt: `Write a short, polite payment reminder for invoice ${invoice.number} (${formatMoney(invoice.amountCents, invoice.currency)}). Context: ${invoice.notes ?? "none"}`,
  });

  await sendEmail({
    to: invoice.to,
    subject: `Payment reminder: invoice ${invoice.number}`,
    html: `<p>${escapeHtml(text).replace(/\n/g, "<br>")}</p>`,
  });
  return { ok: true };
}
