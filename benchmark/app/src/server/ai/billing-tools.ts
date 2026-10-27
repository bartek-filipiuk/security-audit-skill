import { tool } from "ai";
import { and, eq } from "drizzle-orm";
import { z } from "zod";
import { db } from "@/db";
import { invoices } from "@/db/schema";

export function buildBillingTools(ctx: { orgId: string; userId: string }) {
  return {
    voidInvoice: tool({
      description: "Void an invoice of the current organization so it can no longer be paid.",
      inputSchema: z.object({ invoiceId: z.string().describe("Id of the invoice to void") }),
      execute: async ({ invoiceId }) => {
        const [row] = await db
          .update(invoices)
          .set({ status: "void" })
          .where(eq(invoices.id, invoiceId))
          .returning({ number: invoices.number, status: invoices.status });
        return row ?? { error: "not_found" };
      },
    }),

    markInvoicePaid: tool({
      description: "Mark an invoice of the current organization as paid. The user confirms each call.",
      inputSchema: z.object({ invoiceId: z.string() }),
      needsApproval: true,
      execute: async ({ invoiceId }) => {
        const [row] = await db
          .update(invoices)
          .set({ status: "paid", paidAt: new Date() })
          .where(and(eq(invoices.id, invoiceId), eq(invoices.orgId, ctx.orgId)))
          .returning({ number: invoices.number, status: invoices.status });
        return row ?? { error: "not_found" };
      },
    }),
  };
}
