"use client";

import { useEffect, useState } from "react";

type Stats = {
  users: number;
  organizations: number;
  projects: number;
  recentSignups: { id: string; name: string; email: string; createdAt: string }[];
};

export function AdminStats() {
  const [stats, setStats] = useState<Stats | null>(null);

  useEffect(() => {
    fetch("/api/admin/stats")
      .then((r) => r.json())
      .then(setStats);
  }, []);

  if (!stats) return <p>Loading…</p>;
  return (
    <div>
      <p>
        {stats.users} users · {stats.organizations} organizations · {stats.projects} projects
      </p>
      <ul>
        {stats.recentSignups.map((u) => (
          <li key={u.id}>
            {u.name} ({u.email})
          </li>
        ))}
      </ul>
    </div>
  );
}
