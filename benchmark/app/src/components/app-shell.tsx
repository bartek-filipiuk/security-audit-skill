import Link from "next/link";
import type { ReactNode } from "react";

export function AppShell({ user, children }: { user: { name: string; email: string }; children: ReactNode }) {
  return (
    <div className="shell">
      <nav>
        <Link href="/dashboard">Dashboard</Link>
        <Link href="/projects">Projects</Link>
        <Link href="/invoices">Invoices</Link>
        <Link href="/assistant">Assistant</Link>
        <Link href="/settings/team">Team</Link>
        <Link href="/settings/notifications">Notifications</Link>
        <Link href="/settings/billing">Billing</Link>
        <span>{user.name}</span>
      </nav>
      <main>{children}</main>
    </div>
  );
}
