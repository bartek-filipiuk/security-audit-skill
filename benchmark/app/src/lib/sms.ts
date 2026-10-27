import "server-only";

export type SmsResult = { id: string; segments: number };

// SMS gateway client. The provider bills every 160-character segment to Ledgerly's account.
export async function sendSms(input: { to: string; body: string }): Promise<SmsResult> {
  const res = await fetch(process.env.SMS_GATEWAY_URL!, {
    method: "POST",
    headers: { authorization: `Bearer ${process.env.SMS_API_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({ to: input.to, from: "Ledgerly", text: input.body }),
    signal: AbortSignal.timeout(5000),
  });
  if (!res.ok) throw new Error(`SMS delivery failed: ${res.status}`);
  return (await res.json()) as SmsResult;
}
