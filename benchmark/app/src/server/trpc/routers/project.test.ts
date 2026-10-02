import { describe, expect, it, vi } from "vitest";

vi.mock("@/db", () => ({ db: {} }));
vi.mock("@/lib/auth", () => ({ auth: { api: { getSession: vi.fn() } } }));

describe("projectRouter", () => {
  it("lists projects for the active organization", async () => {
    const rows = [{ id: "p1", orgId: "org1", name: "Website" }];
    const db = {
      select: () => ({ from: () => ({ where: () => ({ orderBy: async () => rows }) }) }),
    };
    const { projectRouter } = await import("./project");
    const caller = projectRouter.createCaller({
      db: db as never,
      session: { user: { id: "u1" }, session: { activeOrganizationId: "org1" } } as never,
    });
    await expect(caller.list()).resolves.toEqual(rows);
  });

  it("updates a project name", async () => {
    const db = {
      update: () => ({ set: () => ({ where: () => ({ returning: async () => [{ id: "p1", name: "New" }] }) }) }),
    };
    const { projectRouter } = await import("./project");
    const caller = projectRouter.createCaller({
      db: db as never,
      session: { user: { id: "u1" }, session: { activeOrganizationId: "org1" } } as never,
    });
    const result = await caller.update({ id: "p1", name: "New" });
    expect(result.name).toBe("New");
  });
});
