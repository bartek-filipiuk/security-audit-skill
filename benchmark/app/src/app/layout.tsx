import type { ReactNode } from "react";
import "./globals.css";

export const metadata = { title: "Ledgerly", description: "Invoicing for small agencies" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
