import { NextResponse } from "next/server";
import {
  assertPublicTarget,
  normalizePublicUrl,
  type ReportLanguage,
  scanWebsite,
} from "@/lib/security-scanner";

export const runtime = "nodejs";
export const maxDuration = 90;

export async function POST(request: Request) {
  const body = (await request.json().catch(() => null)) as {
    language?: unknown;
    url?: unknown;
  } | null;

  const input = typeof body?.url === "string" ? body.url.trim() : "";
  const language: ReportLanguage = body?.language === "en" ? "en" : "mn";

  if (!input) {
    return NextResponse.json({ error: "Enter a website URL to scan." }, { status: 400 });
  }

  try {
    const url = normalizePublicUrl(input);
    await assertPublicTarget(url);
    const data = await scanWebsite(url, language);

    return NextResponse.json({ data });
  } catch (error) {
    const message =
      error instanceof Error ? error.message : "Unable to scan this website.";

    return NextResponse.json({ error: message }, { status: 400 });
  }
}
