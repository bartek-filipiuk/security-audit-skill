import { TRPCError } from "@trpc/server";
import { desc, eq } from "drizzle-orm";
import { z } from "zod";
import { projects } from "@/db/schema";
import { orgProcedure, router } from "../init";

export const projectRouter = router({
  list: orgProcedure.query(({ ctx }) =>
    ctx.db.select().from(projects).where(eq(projects.orgId, ctx.orgId)).orderBy(desc(projects.createdAt)),
  ),

  update: orgProcedure
    .input(
      z.object({
        id: z.string(),
        name: z.string().min(1).max(120).optional(),
        description: z.string().max(2000).optional(),
        internalNotes: z.string().max(5000).optional(),
        isPublic: z.boolean().optional(),
      }),
    )
    .mutation(async ({ ctx, input }) => {
      const { id, ...patch } = input;
      const [updated] = await ctx.db.update(projects).set(patch).where(eq(projects.id, id)).returning();
      if (!updated) throw new TRPCError({ code: "NOT_FOUND" });
      return updated;
    }),
});
