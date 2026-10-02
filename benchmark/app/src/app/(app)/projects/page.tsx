import { ProjectList } from "@/components/project-list";
import { requireOrg } from "@/lib/session";

export default async function ProjectsPage() {
  await requireOrg();
  return (
    <section>
      <h1>Projects</h1>
      <ProjectList />
    </section>
  );
}
