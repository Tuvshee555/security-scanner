import { NextResponse } from "next/server";
import { scrapeTripadvisor } from "@/lib/tripadvisor";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(request: Request) {
  const body = (await request.json().catch(() => null)) as {
    url?: unknown;
  } | null;

  const url = typeof body?.url === "string" ? body.url.trim() : "";

  if (!url) {
    return NextResponse.json({ error: "A TripAdvisor URL is required." }, { status: 400 });
  }

  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return NextResponse.json({ error: "Enter a valid URL." }, { status: 400 });
  }

  if (!parsed.hostname.includes("tripadvisor.")) {
    return NextResponse.json(
      { error: "Only TripAdvisor URLs are supported." },
      { status: 400 },
    );
  }

  try {
    const data = await scrapeTripadvisor(parsed.toString());
    return NextResponse.json({ data });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unable to scrape this page.";

    return NextResponse.json({ error: message }, { status: 500 });
  }
}
