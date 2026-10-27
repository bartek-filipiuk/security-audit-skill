import { notFound } from "next/navigation";
import { InvoiceDetail } from "@/components/invoice-detail";
import { SignatureFrame } from "@/components/signature-frame";
import { getInvoice } from "../actions";

export default async function InvoicePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const invoice = await getInvoice(id);
  if (!invoice) notFound();
  return (
    <>
      <InvoiceDetail invoice={invoice} />
      {invoice.status === "open" && <SignatureFrame invoiceId={id} />}
    </>
  );
}
