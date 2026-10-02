import { count, desc } from "drizzle-orm";
import { db } from "@/db";
import { organization, projects, subscriptions, user } from "@/db/schema";

export async function GET() {
  const [users] = await db.select({ total: count() }).from(user);
  const [orgs] = await db.select({ total: count() }).from(organization);
  const [projectCount] = await db.select({ total: count() }).from(projects);
  const recentSignups = await db
    .select({ id: user.id, name: user.name, email: user.email, createdAt: user.createdAt })
    .from(user)
    .orderBy(desc(user.createdAt))
    .limit(25);
  const plans = await db
    .select({ plan: subscriptions.plan, total: count() })
    .from(subscriptions)
    .groupBy(subscriptions.plan);

  return Response.json({
    users: users.total,
    organizations: orgs.total,
    projects: projectCount.total,
    recentSignups,
    plans,
  });
}
