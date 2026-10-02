import { formatDate, formatMoney } from "@/lib/format";

type Invoice = {
  number: string;
  amountCents: number;
  currency: string;
  status: string;
  dueDate: Date;
  notes: string | null;
  lines: { id: string; description: string; quantity: number; unitCents: number }[];
};

export function InvoiceDetail({ invoice }: { invoice: Invoice }) {
  return (
    <article>
      <h1>Invoice {invoice.number}</h1>
      <p>
        {invoice.status} · due {formatDate(invoice.dueDate)} · {formatMoney(invoice.amountCents, invoice.currency)}
      </p>
      <ul>
        {invoice.lines.map((l) => (
          <li key={l.id}>
            {l.quantity} × {l.description} — {formatMoney(l.unitCents, invoice.currency)}
          </li>
        ))}
      </ul>
      {invoice.notes && <p>{invoice.notes}</p>}
    </article>
  );
}
