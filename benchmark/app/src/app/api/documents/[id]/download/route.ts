import { GetObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { and, eq } from "drizzle-orm";
import { db } from "@/db";
import { documents } from "@/db/schema";
import { BUCKET, s3 } from "@/lib/s3";
import { getSession } from "@/lib/session";

export async function GET(_request: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await getSession();
  const orgId = session?.session.activeOrganizationId;
  if (!orgId) return new Response("Unauthorized", { status: 401 });

  const { id } = await params;
  const [doc] = await db
    .select()
    .from(documents)
    .where(and(eq(documents.id, id), eq(documents.orgId, orgId)))
    .limit(1);
  if (!doc) return new Response("Not found", { status: 404 });

  const url = await getSignedUrl(
    s3,
    new GetObjectCommand({
      Bucket: BUCKET,
      Key: doc.s3Key,
      ResponseContentDisposition: `attachment; filename="${encodeURIComponent(doc.filename)}"`,
    }),
    { expiresIn: 60 },
  );
  return Response.redirect(url, 302);
}
