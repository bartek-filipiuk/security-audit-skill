"use client";

import { useChat } from "@ai-sdk/react";
import { generateText } from "ai";
import { useState } from "react";
import { browserAnthropic } from "@/lib/ai-client";

export function AssistantPanel() {
  const { messages, sendMessage, status } = useChat();
  const [input, setInput] = useState("");
  const [suggestion, setSuggestion] = useState("");

  async function suggest() {
    const { text } = await generateText({
      model: browserAnthropic("claude-haiku-4-5"),
      prompt: `Suggest a short, polite payment reminder for this note: ${input}`,
    });
    setSuggestion(text);
  }

  return (
    <section>
      {messages.map((m) => (
        <div key={m.id}>
          <strong>{m.role}</strong>
          {m.parts.map((p, i) => (p.type === "text" ? <p key={i}>{p.text}</p> : null))}
        </div>
      ))}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          sendMessage({ text: input });
          setInput("");
        }}
      >
        <input value={input} onChange={(e) => setInput(e.target.value)} disabled={status === "streaming"} />
        <button type="submit">Ask</button>
        <button type="button" onClick={suggest}>
          Suggest reminder
        </button>
      </form>
      {suggestion && <blockquote>{suggestion}</blockquote>}
    </section>
  );
}
