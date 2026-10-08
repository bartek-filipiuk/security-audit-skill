"use client";

import { BoardList } from "@/components/board-list";

async function renderPng(boardId: string) {
  const canvas = document.querySelector<HTMLCanvasElement>(`canvas[data-board="${boardId}"]`);
  return new Promise<Blob>((resolve) => canvas?.toBlob((b) => resolve(b ?? new Blob()), "image/png") ?? resolve(new Blob()));
}

export default function BoardsPage() {
  return <BoardList renderPng={renderPng} />;
}
