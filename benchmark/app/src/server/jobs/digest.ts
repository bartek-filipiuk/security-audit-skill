import type { Job } from "pg-boss";
import { and, eq, lt } from "drizzle-orm";
import { db } from "@/db";
import { customers, invoices, organization, user } from "@/db/schema";
import { sendEmail } from "@/lib/email";
import { formatDate, formatMoney } from "@/lib/format";

export type DigestJob = { orgId: string };

export async function sendOverdueDigest([job]: Job<DigestJob>[]) {
  const { orgId } = job.data;

  const [org] = await db.select().from(organization).where(eq(organization.id, orgId)).limit(1);
  if (!org) return;

  const overdue = await db
    .select({
      number: invoices.number,
      amountCents: invoices.amountCents,
      dueDate: invoices.dueDate,
      customer: customers.name,
    })
    .from(invoices)
    .innerJoin(customers, eq(customers.id, invoices.customerId))
    .where(and(eq(invoices.orgId, orgId), eq(invoices.status, "open"), lt(invoices.dueDate, new Date())));
  if (overdue.length === 0) return;

  const recipients = await db
    .select({ email: user.email, name: user.name })
    .from(user)
    .where(eq(user.emailDigest, true));

  const rows = overdue
    .map((i) => `<tr><td>${i.number}</td><td>${i.customer}</td><td>${formatMoney(i.amountCents)}</td><td>${formatDate(i.dueDate)}</td></tr>`)
    .join("");

  for (const r of recipients) {
    await sendEmail({
      to: r.email,
      subject: `${org.name}: ${overdue.length} overdue invoices`,
      html: `<p>Hi ${r.name},</p><table>${rows}</table>`,
    });
  }
}
