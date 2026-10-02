import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);

export async function sendEmail(input: { to: string; subject: string; html: string }) {
  const { error } = await resend.emails.send({
    from: "Ledgerly <notifications@ledgerly.app>",
    to: input.to,
    subject: input.subject,
    html: input.html,
  });
  if (error) throw new Error(`Email delivery failed: ${error.message}`);
}
