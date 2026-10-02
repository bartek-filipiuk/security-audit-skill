import { eq } from "drizzle-orm";
import { db } from "@/db";
import { customers } from "@/db/schema";
import { getSession } from "@/lib/session";

export async function GET(request: Request) {
  const session = await getSession();
  if (!session) return new Response("Unauthorized", { status: 401 });

  const { searchParams } = new URL(request.url);
  const orgId = searchParams.get("org") ?? session.session.activeOrganizationId;
  if (!orgId) return new Response("No organization selected", { status: 400 });

  const rows = await db
    .select({
      name: customers.name,
      email: customers.email,
      phone: customers.phone,
      taxId: customers.taxId,
      createdAt: customers.createdAt,
    })
    .from(customers)
    .where(eq(customers.orgId, orgId));

  const header = "name,email,phone,tax_id,created_at";
  const body = rows.map((r) =>
    [r.name, r.email, r.phone ?? "", r.taxId ?? "", r.createdAt.toISOString()].map(csvCell).join(","),
  );

  return new Response([header, ...body].join("\n"), {
    headers: {
      "content-type": "text/csv; charset=utf-8",
      "content-disposition": `attachment; filename="customers-${orgId}.csv"`,
    },
  });
}

function csvCell(value: string) {
  return /[",\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}
