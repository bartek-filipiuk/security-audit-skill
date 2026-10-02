import { PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import { z } from "zod";
import { db } from "@/db";
import { documents } from "@/db/schema";
import { BUCKET, s3 } from "@/lib/s3";
import { getSession } from "@/lib/session";

const uploadInput = z.object({
  projectId: z.string().min(1),
  filename: z.string().min(1).max(200),
  contentType: z.string().min(1),
  key: z.string().min(1),
});

export async function POST(request: Request) {
  const session = await getSession();
  const orgId = session?.session.activeOrganizationId;
  if (!session || !orgId) return new Response("Unauthorized", { status: 401 });

  const input = uploadInput.parse(await request.json());

  const url = await getSignedUrl(
    s3,
    new PutObjectCommand({ Bucket: BUCKET, Key: input.key, ContentType: input.contentType }),
    { expiresIn: 900 },
  );

  await db.insert(documents).values({
    id: crypto.randomUUID(),
    orgId,
    projectId: input.projectId,
    s3Key: input.key,
    filename: input.filename,
    contentType: input.contentType,
    uploadedBy: session.user.id,
  });

  return Response.json({ url, key: input.key });
}
