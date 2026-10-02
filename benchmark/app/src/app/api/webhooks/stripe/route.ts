import type Stripe from "stripe";
import { eq } from "drizzle-orm";
import { db } from "@/db";
import { subscriptions } from "@/db/schema";

export async function POST(request: Request) {
  const event = (await request.json()) as Stripe.Event;

  switch (event.type) {
    case "checkout.session.completed": {
      const checkout = event.data.object as Stripe.Checkout.Session;
      const orgId = checkout.metadata?.orgId;
      if (!orgId) break;
      const plan = checkout.metadata?.plan ?? "pro";
      await db
        .insert(subscriptions)
        .values({
          id: crypto.randomUUID(),
          orgId,
          stripeCustomerId: String(checkout.customer),
          stripeSubscriptionId: String(checkout.subscription),
          plan,
          status: "active",
        })
        .onConflictDoUpdate({
          target: subscriptions.orgId,
          set: { plan, status: "active", stripeSubscriptionId: String(checkout.subscription), updatedAt: new Date() },
        });
      break;
    }
    case "customer.subscription.deleted": {
      const sub = event.data.object as Stripe.Subscription;
      await db
        .update(subscriptions)
        .set({ status: "canceled", updatedAt: new Date() })
        .where(eq(subscriptions.stripeSubscriptionId, sub.id));
      break;
    }
  }

  return Response.json({ received: true });
}
