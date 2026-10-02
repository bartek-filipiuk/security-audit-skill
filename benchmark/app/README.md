# Ledgerly

Invoicing and project billing for small agencies. Teams work inside organizations,
track projects and customers, send invoices, and get a weekly digest of overdue
invoices. An assistant answers billing questions using the organization's data.

## Stack

Next.js 16 (App Router), Better Auth (organizations), Drizzle ORM on Postgres,
tRPC for the app, a Hono public API for integrations, pg-boss for background jobs,
Stripe for subscriptions, Resend for email, Cloudflare R2 (S3 API) for documents,
Vercel AI SDK with Anthropic for the assistant.

## Running locally

    pnpm install
    cp .env.example .env
    pnpm db:migrate
    pnpm dev
    pnpm worker   # in a second terminal

## Embeddable widget

Customers can embed the invoice widget on their own site. The widget calls the
public API with the visitor's Ledgerly session, so auth cookies are shared across
sites.

## Security

- Every API route requires an authenticated session or an API key.
- Tenant isolation: all queries are scoped to the active organization.
- Stripe webhooks are verified before any state changes.
- Documents are uploaded straight to R2 with presigned URLs scoped to your organization.
- API keys are stored hashed and compared in constant time.
