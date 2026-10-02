"use client";

import { useState } from "react";
import { getInvoice } from "@/app/(app)/invoices/actions";
import { formatMoney } from "@/lib/format";

type Preview = Awaited<ReturnType<typeof getInvoice>>;

export function InvoiceQuickView({ id }: { id: string }) {
  const [preview, setPreview] = useState<Preview>(null);

  return (
    <span onMouseEnter={async () => setPreview(await getInvoice(id))}>
      Preview
      {preview && (
        <span role="tooltip">
          {preview.lines.length} lines · {formatMoney(preview.amountCents, preview.currency)}
        </span>
      )}
    </span>
  );
}
