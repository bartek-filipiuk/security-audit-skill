import { router } from "./init";
import { integrationRouter } from "./routers/integration";
import { invoiceRouter } from "./routers/invoice";
import { projectRouter } from "./routers/project";

export const appRouter = router({
  project: projectRouter,
  invoice: invoiceRouter,
  integration: integrationRouter,
});

export type AppRouter = typeof appRouter;
