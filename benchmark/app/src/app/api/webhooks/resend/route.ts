import { inArray } from "drizzle-orm";
import { Webhook } from "svix";
import { db } from "@/db";
import { user } from "@/db/schema";

type ResendEvent = { type: string; data: { email_id: string; to: string[] } };

export async function POST(request: Request) {
  const payload = await request.text();
  const wh = new Webhook(process.env.RESEND_WEBHOOK_SECRET!);

  let event: ResendEvent;
  try {
    event = wh.verify(payload, {
      "svix-id": request.headers.get("svix-id") ?? "",
      "svix-timestamp": request.headers.get("svix-timestamp") ?? "",
      "svix-signature": request.headers.get("svix-signature") ?? "",
    }) as ResendEvent;
  } catch {
    return new Response("Invalid signature", { status: 400 });
  }

  if (event.type === "email.bounced" || event.type === "email.complained") {
    await db.update(user).set({ emailDigest: false }).where(inArray(user.email, event.data.to));
  }

  return Response.json({ ok: true });
}
