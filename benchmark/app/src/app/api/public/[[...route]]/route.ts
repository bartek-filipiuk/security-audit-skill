import { handle } from "hono/vercel";
import { api } from "@/server/api";

export const GET = handle(api);
export const POST = handle(api);
export const OPTIONS = handle(api);
