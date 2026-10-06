"use client";

import { useTransition } from "react";
import { sendAiReminder } from "./actions";

export function SendReminderButton({ invoiceId }: { invoiceId: string }) {
  const [pending, start] = useTransition();
  return (
    <button type="button" disabled={pending} onClick={() => start(() => sendAiReminder(invoiceId))}>
      Send AI-drafted reminder
    </button>
  );
}
