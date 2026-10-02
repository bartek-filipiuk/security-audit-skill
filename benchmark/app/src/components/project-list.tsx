"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { useTRPC } from "@/lib/trpc-client";

export function ProjectList() {
  const trpc = useTRPC();
  const { data, refetch } = useQuery(trpc.project.list.queryOptions());
  const update = useMutation(trpc.project.update.mutationOptions({ onSuccess: () => refetch() }));

  return (
    <ul>
      {data?.map((p) => (
        <li key={p.id}>
          {p.name}
          <label>
            <input
              type="checkbox"
              checked={p.isPublic}
              onChange={(e) => update.mutate({ id: p.id, isPublic: e.target.checked })}
            />
            Public page
          </label>
        </li>
      ))}
    </ul>
  );
}
