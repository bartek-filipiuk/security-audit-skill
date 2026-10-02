import type { ReactNode } from "react";
import { AppShell } from "@/components/app-shell";
import { requireOrg } from "@/lib/session";

export default async function AppLayout({ children }: { children: ReactNode }) {
  const { session } = await requireOrg();
  return <AppShell user={{ name: session.user.name, email: session.user.email }}>{children}</AppShell>;
}
