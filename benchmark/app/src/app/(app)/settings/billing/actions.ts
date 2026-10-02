"use server";

import { redirect } from "next/navigation";
import { z } from "zod";
import { requireOrg } from "@/lib/session";
import { PRICES, stripe } from "@/lib/stripe";

const planInput = z.enum(["pro", "team"]);

export async function startCheckout(plan: z.infer<typeof planInput>) {
  const { session, orgId } = await requireOrg();
  const selected = planInput.parse(plan);
  const checkout = await stripe.checkout.sessions.create({
    mode: "subscription",
    customer_email: session.user.email,
    line_items: [{ price: PRICES[selected], quantity: 1 }],
    metadata: { orgId, plan: selected },
    success_url: `${process.env.APP_URL}/settings/billing?status=success`,
    cancel_url: `${process.env.APP_URL}/settings/billing`,
  });
  redirect(checkout.url!);
}
