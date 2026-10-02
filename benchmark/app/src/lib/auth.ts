import { betterAuth } from "better-auth";
import { drizzleAdapter } from "better-auth/adapters/drizzle";
import { nextCookies } from "better-auth/next-js";
import { organization } from "better-auth/plugins";
import { db } from "@/db";
import * as schema from "@/db/schema";
import { sendEmail } from "@/lib/email";

export const auth = betterAuth({
  baseURL: process.env.APP_URL,
  database: drizzleAdapter(db, { provider: "pg", schema }),
  emailAndPassword: {
    enabled: true,
    requireEmailVerification: true,
    minPasswordLength: 10,
  },
  emailVerification: {
    sendOnSignUp: true,
    sendVerificationEmail: async ({ user, url }) => {
      await sendEmail({
        to: user.email,
        subject: "Verify your Ledgerly account",
        html: `<p>Hi ${user.name},</p><p><a href="${url}">Verify your email</a></p>`,
      });
    },
  },
  user: {
    additionalFields: {
      role: { type: "string", defaultValue: "member" },
      emailDigest: { type: "boolean", defaultValue: true },
    },
  },
  rateLimit: { enabled: true, window: 60, max: 20 },
  advanced: {
    crossSubDomainCookies: { enabled: true, domain: ".ledgerly.app" },
    defaultCookieAttributes: { sameSite: "none", secure: true },
  },
  trustedOrigins: [process.env.APP_URL!],
  plugins: [organization({ allowUserToCreateOrganization: true }), nextCookies()],
});

export type Session = typeof auth.$Infer.Session;
