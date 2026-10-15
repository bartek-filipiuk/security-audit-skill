"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { z } from "zod";

// E-signature provider's hosted signing page, embedded on an open invoice for customer acceptance.
const SIGN_ORIGIN = "https://sign.example.com";

const signMessage = z.discriminatedUnion("type", [
  z.object({ type: z.literal("resize"), height: z.number().int().min(200).max(1200) }),
  z.object({ type: z.literal("signed"), reference: z.string().max(64) }),
]);

export function SignatureFrame({ invoiceId }: { invoiceId: string }) {
  const router = useRouter();
  const frame = useRef<HTMLIFrameElement>(null);
  const [height, setHeight] = useState(480);

  useEffect(() => {
    function onMessage(event: MessageEvent) {
      if (event.origin !== SIGN_ORIGIN || event.source !== frame.current?.contentWindow) return;
      const parsed = signMessage.safeParse(event.data);
      if (!parsed.success) return;
      if (parsed.data.type === "resize") setHeight(parsed.data.height);
      // Only re-renders the server page; the message changes no state and navigates nowhere.
      if (parsed.data.type === "signed" && parsed.data.reference === invoiceId) router.refresh();
    }
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [invoiceId, router]);

  return (
    <iframe
      ref={frame}
      title="Sign invoice"
      src={`${SIGN_ORIGIN}/sign?reference=${encodeURIComponent(invoiceId)}`}
      onLoad={() => frame.current?.contentWindow?.postMessage({ type: "ready", reference: invoiceId }, SIGN_ORIGIN)}
      style={{ width: "100%", height, border: 0 }}
    />
  );
}
