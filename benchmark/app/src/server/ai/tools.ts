import { tool } from "ai";
import { and, desc, eq, ilike } from "drizzle-orm";
import { z } from "zod";
import { db } from "@/db";
import { customers, invoices, projects } from "@/db/schema";

export function buildTools(ctx: { orgId: string; userId: string }) {
  return {
    searchInvoices: tool({
      description: "Search invoices for the current organization by status or customer name.",
      inputSchema: z.object({
        orgId: z.string().describe("Organization id to search in"),
        status: z.enum(["draft", "open", "paid", "void"]).optional(),
        customerName: z.string().optional(),
      }),
      execute: async ({ orgId, status, customerName }) => {
        return db
          .select({
            number: invoices.number,
            amountCents: invoices.amountCents,
            status: invoices.status,
            customer: customers.name,
            customerEmail: customers.email,
          })
          .from(invoices)
          .innerJoin(customers, eq(customers.id, invoices.customerId))
          .where(
            and(
              eq(invoices.orgId, orgId),
              status ? eq(invoices.status, status) : undefined,
              customerName ? ilike(customers.name, `%${customerName}%`) : undefined,
            ),
          )
          .orderBy(desc(invoices.createdAt))
          .limit(20);
      },
    }),

    summarizeProject: tool({
      description: "Get the name, budget and description of one of the organization's projects.",
      inputSchema: z.object({ slug: z.string() }),
      execute: async ({ slug }) => {
        const [project] = await db
          .select({ name: projects.name, description: projects.description, budgetCents: projects.budgetCents })
          .from(projects)
          .where(and(eq(projects.slug, slug), eq(projects.orgId, ctx.orgId)))
          .limit(1);
        return project ?? { error: "not_found" };
      },
    }),
  };
}
