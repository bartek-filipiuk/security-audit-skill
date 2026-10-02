"use client";

import type { InferSelectModel } from "drizzle-orm";
import type { documents, projects } from "@/db/schema";

type Props = {
  project: InferSelectModel<typeof projects> & { documents: InferSelectModel<typeof documents>[] };
};

export function PublicProjectView({ project }: Props) {
  return (
    <main>
      <h1>{project.name}</h1>
      {project.description && <p>{project.description}</p>}
      <h2>Shared files</h2>
      <ul>
        {project.documents.map((d) => (
          <li key={d.id}>{d.filename}</li>
        ))}
      </ul>
    </main>
  );
}
