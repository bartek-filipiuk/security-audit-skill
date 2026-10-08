import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { invitation, member } from "@/db/schema";
import { sendEmail } from "@/lib/email";
import { getSession } from "@/lib/session";

const ROLES = new Set(["member", "admin"]);

export async function POST(request: Request) {
  const session = await getSession();
  const orgId = session?.session.activeOrganizationId;
  if (!session || !orgId) return new Response("Unauthorized", { status: 401 });

  const [me] = await db
    .select({ role: member.role })
    .from(member)
    .where(and(eq(member.organizationId, orgId), eq(member.userId, session.user.id)))
    .limit(1);
  if (!me || (me.role !== "owner" && me.role !== "admin")) return new Response("Forbidden", { status: 403 });

  const form = await request.formData();
  const email = String(form.get("email") ?? "").trim().toLowerCase();
  const role = String(form.get("role") ?? "member");
  if (!email.includes("@") || !ROLES.has(role)) return new Response("Invalid invitation", { status: 400 });

  const id = crypto.randomUUID();
  await db.insert(invitation).values({
    id,
    organizationId: orgId,
    email,
    role,
    status: "pending",
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    inviterId: session.user.id,
  });

  await sendEmail({
    to: email,
    subject: "You have been invited to Ledgerly",
    html: `<p><a href="${process.env.APP_URL}/accept-invitation/${id}">Accept the invitation</a></p>`,
  });

  return Response.redirect(new URL("/settings/team?invited=1", process.env.APP_URL), 303);
}
