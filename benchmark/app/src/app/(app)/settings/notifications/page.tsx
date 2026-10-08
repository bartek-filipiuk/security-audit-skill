import { requireUser } from "@/lib/session";
import { updateNotifications } from "./actions";

export default async function NotificationsPage() {
  const session = await requireUser();
  const digest = Boolean((session.user as { emailDigest?: boolean }).emailDigest);

  return (
    <section>
      <h1>Notifications</h1>
      <form action={updateNotifications}>
        <label>
          <input type="checkbox" name="emailDigest" defaultChecked={digest} /> Weekly digest of overdue invoices
        </label>
        <button type="submit">Save</button>
      </form>
    </section>
  );
}
