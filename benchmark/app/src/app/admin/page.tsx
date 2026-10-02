import { AdminStats } from "@/components/admin-stats";
import { requireAdmin } from "@/lib/session";

export default async function AdminPage() {
  await requireAdmin();
  return (
    <section>
      <h1>Admin</h1>
      <AdminStats />
    </section>
  );
}
