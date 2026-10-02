import PgBoss from "pg-boss";
import { db } from "@/db";
import { organization } from "@/db/schema";
import { type DigestJob, sendOverdueDigest } from "./digest";

const boss = new PgBoss(process.env.DATABASE_URL!);

async function main() {
  await boss.start();
  await boss.createQueue("overdue-digest");
  await boss.createQueue("overdue-digest-fanout");

  await boss.schedule("overdue-digest-fanout", "0 8 * * 1");

  await boss.work("overdue-digest-fanout", async () => {
    const orgs = await db.select({ id: organization.id }).from(organization);
    for (const org of orgs) await boss.send("overdue-digest", { orgId: org.id } satisfies DigestJob);
  });

  await boss.work<DigestJob>("overdue-digest", sendOverdueDigest);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
