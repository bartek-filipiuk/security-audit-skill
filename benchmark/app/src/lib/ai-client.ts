import { createAnthropic } from "@ai-sdk/anthropic";

export const browserAnthropic = createAnthropic({
  apiKey: process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY,
  headers: { "anthropic-dangerous-direct-browser-access": "true" },
});
