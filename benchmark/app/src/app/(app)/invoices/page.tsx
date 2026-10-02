import Link from "next/link";
import { desc, eq } from "drizzle-orm";
import { db } from "@/db";
import { invoices } from "@/db/schema";
import { InvoiceQuickView } from "@/components/invoice-quick-view";
import { formatDate, formatMoney } from "@/lib/format";
import { requireOrg } from "@/lib/session";

export default async function InvoicesPage() {
  const { orgId } = await requireOrg();
  const rows = await db
    .select({
      id: invoices.id,
      number: invoices.number,
      amountCents: invoices.amountCents,
      status: invoices.status,
      dueDate: invoices.dueDate,
    })
    .from(invoices)
    .where(eq(invoices.orgId, orgId))
    .orderBy(desc(invoices.createdAt));

  return (
    <table>
      <tbody>
        {rows.map((inv) => (
          <tr key={inv.id}>
            <td>
              <Link href={`/invoices/${inv.id}`}>{inv.number}</Link>
            </td>
            <td>{formatMoney(inv.amountCents)}</td>
            <td>{inv.status}</td>
            <td>{formatDate(inv.dueDate)}</td>
            <td>
              <InvoiceQuickView id={inv.id} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
