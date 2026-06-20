function getEnv(key: string): string {
  const val = process.env[key];
  if (!val) throw new Error(`Missing env var: ${key}. Add it to Vercel → Settings → Environment Variables.`);
  return val;
}

async function getToken(): Promise<string> {
  const BASE_URL = getEnv("QPAY_BASE_URL");
  const credentials = Buffer.from(`${getEnv("QPAY_USERNAME")}:${getEnv("QPAY_PASSWORD")}`).toString("base64");
  const res = await fetch(`${BASE_URL}/auth/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/json",
    },
  });
  if (!res.ok) {
    const body = await res.text().catch(() => "");
    throw new Error(`QPay auth failed (${res.status}): ${body.slice(0, 200)}`);
  }
  const data = (await res.json()) as { access_token: string };
  return data.access_token;
}

export interface QpayInvoice {
  invoice_id: string;
  qr_text: string;
  qr_image: string;
  urls: { name: string; description: string; logo: string; link: string; deeplink: string }[];
}

export async function createInvoice(options: {
  invoiceNo: string;
  description: string;
  amount: number;
  callbackUrl: string;
}): Promise<QpayInvoice> {
  const BASE_URL = getEnv("QPAY_BASE_URL");
  const INVOICE_CODE = getEnv("QPAY_INVOICE_CODE");
  const token = await getToken();
  const res = await fetch(`${BASE_URL}/invoice`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      invoice_code: INVOICE_CODE,
      sender_invoice_no: options.invoiceNo,
      invoice_receiver_code: "terminal",
      invoice_description: options.description,
      amount: options.amount,
      callback_url: options.callbackUrl,
    }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`QPay invoice failed: ${res.status} ${text.slice(0, 200)}`);
  }
  return res.json() as Promise<QpayInvoice>;
}

export interface QpayPaymentCheck {
  count: number;
  paid_amount: number;
  rows: { payment_id: string; payment_status: string }[];
}

export async function checkPayment(invoiceId: string): Promise<QpayPaymentCheck> {
  const BASE_URL = getEnv("QPAY_BASE_URL");
  const token = await getToken();
  const res = await fetch(`${BASE_URL}/payment/check/${invoiceId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`QPay check failed: ${res.status}`);
  return res.json() as Promise<QpayPaymentCheck>;
}
