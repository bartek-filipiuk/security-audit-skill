"use client";

import { useEffect, useState } from "react";

// Hosted card form of the payment provider, embedded on Settings → Billing.
const WIDGET_URL = "https://billing-widget.example.com/card-form";

type WidgetMessage = { type: "resize"; height: number } | { type: "redirect"; url: string };

export function PaymentMethodFrame({ customerRef }: { customerRef: string }) {
  const [height, setHeight] = useState(320);

  useEffect(() => {
    function onMessage(event: MessageEvent<WidgetMessage>) {
      const msg = event.data;
      if (msg?.type === "resize") setHeight(msg.height);
      // After 3-D Secure the widget asks the page to continue on the provider's confirmation URL.
      if (msg?.type === "redirect") window.location.assign(msg.url);
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, []);

  return (
    <iframe
      title="Payment method"
      src={`${WIDGET_URL}?customer=${encodeURIComponent(customerRef)}`}
      style={{ width: "100%", height, border: 0 }}
    />
  );
}
