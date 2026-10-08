import { anthropic } from "@ai-sdk/anthropic";
import { generateText } from "ai";
import { and, eq } from "drizzle-orm";
import { notFound } from "next/navigation";
import { db } from "@/db";
import { customers, invoiceLines, invoices } from "@/db/schema";
import { requireOrg } from "@/lib/session";
import { SendReminderButton } from "./send-reminder-button";

export default async function InvoiceSummaryPage({ params }: { params: Promise<{ id: string }> }) {
  const { orgId } = await requireOrg();
  const { id } = await params;

  const [invoice] = await db
    .select({ id: invoices.id, number: invoices.number, notes: invoices.notes, customer: customers.name })
    .from(invoices)
    .innerJoin(customers, eq(customers.id, invoices.customerId))
    .where(and(eq(invoices.id, id), eq(invoices.orgId, orgId)))
    .limit(1);
  if (!invoice) notFound();
  const lines = await db.select().from(invoiceLines).where(eq(invoiceLines.invoiceId, invoice.id));

  const { text: summaryHtml } = await generateText({
    model: anthropic("claude-haiku-4-5"),
    maxOutputTokens: 400,
    system: "Summarise the invoice for the account manager. Answer with an HTML fragment using <p>, <ul> and <strong>.",
    prompt: [
      `Invoice ${invoice.number} for ${invoice.customer}.`,
      `Notes: ${invoice.notes ?? "none"}`,
      ...lines.map((l) => `- ${l.quantity} x ${l.description}`),
    ].join("\n"),
  });

  return (
    <article>
      <h1>Invoice {invoice.number}: summary</h1>
      <div dangerouslySetInnerHTML={{ __html: summaryHtml }} />
      <SendReminderButton invoiceId={invoice.id} />
    </article>
  );
}
