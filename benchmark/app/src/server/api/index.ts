import { Hono } from "hono";
import { cors } from "hono/cors";
import { desc, eq } from "drizzle-orm";
import { db } from "@/db";
import { invoices, projects } from "@/db/schema";
import { auth } from "@/lib/auth";
import { verifyApiKey } from "./keys";

type Vars = { orgId: string };

export const api = new Hono<{ Variables: Vars }>().basePath("/api/public");

api.use(
  "*",
  cors({
    origin: (origin) => origin,
    credentials: true,
    allowMethods: ["GET", "POST", "OPTIONS"],
  }),
);

api.use("*", async (c, next) => {
  const header = c.req.header("authorization");
  if (header?.startsWith("Bearer ")) {
    const key = await verifyApiKey(header.slice(7));
    if (!key) return c.json({ error: "invalid_api_key" }, 401);
    c.set("orgId", key.orgId);
    return next();
  }

  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  const orgId = session?.session.activeOrganizationId;
  if (!orgId) return c.json({ error: "unauthorized" }, 401);
  c.set("orgId", orgId);
  return next();
});

api.get("/invoices", async (c) => {
  const rows = await db
    .select({
      number: invoices.number,
      amountCents: invoices.amountCents,
      currency: invoices.currency,
      status: invoices.status,
      dueDate: invoices.dueDate,
    })
    .from(invoices)
    .where(eq(invoices.orgId, c.get("orgId")))
    .orderBy(desc(invoices.createdAt))
    .limit(100);
  return c.json({ data: rows });
});

api.get("/projects", async (c) => {
  const rows = await db
    .select({ id: projects.id, name: projects.name, slug: projects.slug })
    .from(projects)
    .where(eq(projects.orgId, c.get("orgId")));
  return c.json({ data: rows });
});
