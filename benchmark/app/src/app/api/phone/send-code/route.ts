import { createHash, randomInt } from "node:crypto";
import { z } from "zod";
import { db } from "@/db";
import { verification } from "@/db/schema";
import { sendSms } from "@/lib/sms";

const sendCodeInput = z.object({ phone: z.string().regex(/^\+[1-9]\d{6,14}$/) });

// Sign-up step 2: text a one-time code to the phone number the visitor entered.
export async function POST(request: Request) {
  const { phone } = sendCodeInput.parse(await request.json());
  const code = String(randomInt(100000, 1000000));

  await db.insert(verification).values({
    id: crypto.randomUUID(),
    identifier: `phone:${phone}`,
    value: createHash("sha256").update(code).digest("hex"),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
  });

  await sendSms({ to: phone, body: `Your Ledgerly verification code is ${code}` });
  return Response.json({ ok: true });
}
