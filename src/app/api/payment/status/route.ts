import { NextResponse } from "next/server";
import { checkPayment } from "@/lib/qpay";

export const runtime = "nodejs";

export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const invoiceId = searchParams.get("invoice_id");

  if (!invoiceId) {
    return NextResponse.json({ error: "Missing invoice_id" }, { status: 400 });
  }

  try {
    const result = await checkPayment(invoiceId);
    const paid =
      result.count > 0 &&
      result.rows?.some((row) => row.payment_status === "PAID");
    return NextResponse.json({ paid });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Status check failed";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
