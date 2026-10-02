import { notFound } from "next/navigation";
import { PublicProjectView } from "@/components/public-project-view";
import { db } from "@/db";

export default async function PublicProjectPage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const project = await db.query.projects.findFirst({
    where: (p, { and, eq }) => and(eq(p.slug, slug), eq(p.isPublic, true)),
    with: { documents: true },
  });
  if (!project) notFound();
  return <PublicProjectView project={project} />;
}
