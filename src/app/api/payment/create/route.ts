import { NextResponse } from "next/server";
import { createInvoice } from "@/lib/qpay";

export const runtime = "nodejs";

const REPORT_PRICE = 9900;

export async function POST(request: Request) {
  const body = (await request.json().catch(() => null)) as { url?: unknown } | null;
  const targetUrl = typeof body?.url === "string" ? body.url.slice(0, 80) : "unknown";

  const invoiceNo = `SEC-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

  const host = request.headers.get("host") ?? "localhost:3000";
  const proto = host.startsWith("localhost") || host.startsWith("127.") ? "http" : "https";
  const callbackUrl = `${proto}://${host}/api/payment/callback?invoice_no=${invoiceNo}`;

  try {
    const invoice = await createInvoice({
      invoiceNo,
      description: `Аюулгүй байдлын тайлан: ${targetUrl}`,
      amount: REPORT_PRICE,
      callbackUrl,
    });

    return NextResponse.json({
      invoiceId: invoice.invoice_id,
      qrImage: invoice.qr_image,
      qrText: invoice.qr_text,
      urls: invoice.urls,
      amount: REPORT_PRICE,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Payment creation failed";
    console.error("[payment/create]", message);
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
