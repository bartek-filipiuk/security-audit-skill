import { eq } from "drizzle-orm";
import { db } from "@/db";
import { invitation } from "@/db/schema";
import { requireOrg } from "@/lib/session";

export default async function TeamPage() {
  const { orgId } = await requireOrg();
  const pending = await db
    .select({ id: invitation.id, email: invitation.email, role: invitation.role })
    .from(invitation)
    .where(eq(invitation.organizationId, orgId));

  return (
    <section>
      <h1>Team</h1>
      <form action="/api/team/invite" method="post">
        <input name="email" type="email" required placeholder="name@company.com" />
        <select name="role" defaultValue="member">
          <option value="member">Member</option>
          <option value="admin">Admin</option>
        </select>
        <button type="submit">Send invitation</button>
      </form>
      <ul>
        {pending.map((i) => (
          <li key={i.id}>
            {i.email} ({i.role})
          </li>
        ))}
      </ul>
    </section>
  );
}
