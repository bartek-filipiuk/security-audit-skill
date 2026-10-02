import { eq } from "drizzle-orm";
import { db } from "@/db";
import { subscriptions } from "@/db/schema";
import { requireOrg } from "@/lib/session";
import { startCheckout } from "./actions";

export default async function BillingPage() {
  const { orgId } = await requireOrg();
  const [sub] = await db.select().from(subscriptions).where(eq(subscriptions.orgId, orgId)).limit(1);

  return (
    <section>
      <h1>Billing</h1>
      <p>Current plan: {sub?.plan ?? "free"}</p>
      <form action={startCheckout.bind(null, "pro")}>
        <button type="submit">Upgrade to Pro</button>
      </form>
      <form action={startCheckout.bind(null, "team")}>
        <button type="submit">Upgrade to Team</button>
      </form>
    </section>
  );
}
