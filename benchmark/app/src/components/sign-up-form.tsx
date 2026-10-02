"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";
import { authClient } from "@/lib/auth-client";

export function SignUpForm() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(form: FormData) {
    const { error } = await authClient.signUp.email({
      name: String(form.get("name")),
      email: String(form.get("email")),
      password: String(form.get("password")),
    });
    if (error) return setError(error.message ?? "Sign up failed");
    router.push("/check-your-inbox");
  }

  return (
    <form action={onSubmit}>
      <input name="name" required />
      <input name="email" type="email" required />
      <input name="password" type="password" minLength={10} required />
      {error && <p role="alert">{error}</p>}
      <button type="submit">Create account</button>
    </form>
  );
}
