const SUPPORTED = ["EUR", "USD", "GBP", "PLN"] as const;
export type Currency = (typeof SUPPORTED)[number];

export async function getRates(base: Currency) {
  if (!SUPPORTED.includes(base)) throw new Error("Unsupported currency");
  const res = await fetch(`https://api.frankfurter.app/latest?from=${base}`, {
    next: { revalidate: 3600 },
    signal: AbortSignal.timeout(4000),
  });
  if (!res.ok) throw new Error(`Rates request failed: ${res.status}`);
  const data = (await res.json()) as { rates: Record<string, number> };
  return data.rates;
}
