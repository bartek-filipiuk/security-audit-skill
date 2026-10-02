import { requireOrg } from "@/lib/session";
import { formatMoney } from "@/lib/format";
import { getOrgStats, getUsageThisMonth } from "@/server/queries/dashboard";

export default async function DashboardPage() {
  const { orgId } = await requireOrg();
  const [stats, usage] = await Promise.all([getOrgStats(orgId), getUsageThisMonth(orgId)]);

  return (
    <section>
      <h1>Dashboard</h1>
      <dl>
        <dt>Projects</dt>
        <dd>{stats.projects}</dd>
        <dt>Open invoices</dt>
        <dd>{formatMoney(stats.openInvoiceCents)}</dd>
      </dl>
      <h2>Usage this month</h2>
      <ul>
        {usage.map((u) => (
          <li key={u.kind}>
            {u.kind}: {u.units}
          </li>
        ))}
      </ul>
    </section>
  );
}
