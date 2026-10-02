export function formatMoney(cents: number, currency = "EUR") {
  return new Intl.NumberFormat("en-IE", { style: "currency", currency }).format(cents / 100);
}

export function formatDate(d: Date) {
  return new Intl.DateTimeFormat("en-IE", { dateStyle: "medium" }).format(d);
}
