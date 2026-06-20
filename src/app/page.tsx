"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";

type Severity = "critical" | "high" | "medium" | "low" | "info" | "good";
type Language = "mn" | "en";

interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  evidence: string;
  impact: string;
  recommendation: string;
}

interface Metric {
  label: string;
  score: number;
  weight: number;
  summary: string;
}

interface BrowserSignal {
  finalUrl: string;
  title: string | null;
  forms: number;
  passwordInputs: number;
  externalScripts: number;
  inlineScripts: number;
  mixedContent: string[];
  consoleErrors: string[];
  failedRequests: string[];
}

interface TlsSignal {
  enabled: boolean;
  authorized: boolean | null;
  protocol: string | null;
  cipher: string | null;
  validFrom: string | null;
  validTo: string | null;
  issuer: string | null;
  subject: string | null;
}

interface DnsSignal {
  mx: string[];
  spf: string | null;
  dmarc: string | null;
  caa: string[];
}

interface PageSignal {
  url: string;
  status: number | null;
  title: string | null;
  kind: "home" | "product" | "cart" | "checkout" | "login" | "policy" | "other";
  https: boolean;
  forms: number;
  passwordInputs: number;
  paymentInputs: number;
  scripts: string[];
  providers: string[];
  riskyClientPaymentSignals: string[];
}

interface EcommerceSignal {
  isLikelyEcommerce: boolean;
  platform: string[];
  paymentProviders: string[];
  qpayDetected: boolean;
  pagesChecked: PageSignal[];
  discoveredUrls: string[];
  policies: {
    privacy: boolean;
    terms: boolean;
    refund: boolean;
    contact: boolean;
  };
  cookieConsent: boolean;
  checkoutPages: number;
  cartPages: number;
  loginPages: number;
  suspiciousCheckoutScripts: string[];
  riskyClientPaymentSignals: string[];
  paymentBypassRiskScore: number;
  paymentBypassRiskLevel: "low" | "medium" | "high" | "critical";
  activePaymentBypassTested: false;
  activePaymentBypassNote: string;
}

interface SecurityScanResult {
  inputUrl: string;
  finalUrl: string;
  scannedAt: string;
  status: number | null;
  responseTimeMs: number;
  contentType: string | null;
  headers: Record<string, string>;
  tls: TlsSignal;
  dns: DnsSignal;
  browser: BrowserSignal;
  ecommerce: EcommerceSignal;
  metrics: Metric[];
  findings: Finding[];
  score: number;
  grade: string;
  aiReview: string | null;
  aiModel: string | null;
  aiError: string | null;
}

interface InvoiceData {
  invoiceId: string;
  qrImage: string;
  qrText: string;
  urls: { name: string; description: string; logo: string; link: string; deeplink: string }[];
  amount: number;
}

const defaultUrl = "https://example.com";
const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info", "good"];

const METRIC_LABELS: Record<Language, Record<string, string>> = {
  mn: {
    "Transport": "Холболт",
    "Headers": "Толгой",
    "E-commerce": "Дэлгүүр",
    "Payments": "Төлбөр",
    "DNS / Email": "DNS/Имэйл",
    "Browser Runtime": "Browser",
  },
  en: {},
};

const CATEGORY_LABELS: Record<Language, Record<string, string>> = {
  mn: {
    "Headers": "Толгой",
    "Transport": "Холболт",
    "Cookies": "Cookie",
    "Browser": "Browser",
    "Reliability": "Найдвартай байдал",
    "Forms": "Маягт",
    "E-commerce": "Дэлгүүр",
    "Payments": "Төлбөр",
    "Trust": "Итгэл",
    "DNS": "DNS",
    "Privacy": "Нууцлал",
  },
  en: {},
};

const KIND_LABELS: Record<Language, Record<PageSignal["kind"], string>> = {
  mn: {
    home: "Нүүр",
    product: "Бүтээгдэхүүн",
    cart: "Сагс",
    checkout: "Checkout",
    login: "Нэвтрэх",
    policy: "Бодлого",
    other: "Бусад",
  },
  en: {
    home: "Home",
    product: "Product",
    cart: "Cart",
    checkout: "Checkout",
    login: "Login",
    policy: "Policy",
    other: "Other",
  },
};

const copy = {
  mn: {
    badge: "E-commerce хамгаалалтын лаборатори",
    title:
      "Онлайн дэлгүүр, checkout, QPay, DNS, cookie, privacy, төлбөрийн эрсдэлийг нэг дор шалгана.",
    subtitle:
      "Бодит сайт руу exploit, brute force, үнэгүй худалдан авалт хийхгүй. Харин public evidence-ээр худалдагчид яг юугаа засахыг хэлнэ.",
    url: "Вэбсайт URL",
    run: "Шалгах",
    scanning: "Шалгаж байна...",
    overall: "Ерөнхий аюулгүй байдал",
    target: "Шалгасан сайт",
    score: "Оноо",
    time: "Хугацаа",
    scanned: "Шалгасан огноо",
    findings: "Олдсон зүйлс",
    findingsTitle: "Юу сайн, юу муу, юу яаралтай вэ",
    evidence: "Нотолгоо",
    impact: "Юу болж магадгүй",
    fix: "Засах арга",
    ai: "AI тайлбар",
    aiTitle: "Худалдагчид ойлгомжтой дүгнэлт",
    aiModel: "Загвар",
    ecommerce: "E-commerce",
    shopTitle: "Дэлгүүр ба төлбөр",
    likelyShop: "Дэлгүүр мөн үү",
    checkout: "Checkout",
    cart: "Сагс",
    login: "Нэвтрэх",
    platform: "Платформ",
    payments: "Төлбөр систем",
    bypassRisk: "Bypass эрсдэл",
    privacy: "Нууцлал",
    refund: "Буцаалт",
    cookieConsent: "Cookie зөвшөөрөл",
    dns: "DNS",
    emailDomain: "Имэйл ба домэйн",
    cert: "Сертификат",
    enabled: "Идэвхтэй",
    trusted: "Итгэмжлэгдсэн",
    protocol: "Протокол",
    cipher: "Шифр",
    issuer: "Гаргасан",
    validTo: "Хүчинтэй хүртэл",
    crawlEyebrow: "Шалгалт",
    crawlTitle: "Шалгасан checkout / cart / login хуудсууд",
    kindCol: "Төрөл",
    formsCol: "Маягт",
    providersCol: "Төлбөр",
    runtime: "Browser алдаа ба failed request",
    headers: "Response headers",
    noErrors: "Browser алдаа олдсонгүй.",
    yes: "Тийм",
    no: "Үгүй",
    unknown: "Мэдэгдэхгүй",
    critical: "Аюулт",
    high: "Өндөр",
    medium: "Дунд",
    low: "Бага",
    info: "Мэдээлэл",
    good: "Сайн",
    paymentNote:
      "Тайлбар: live дэлгүүр дээр төлбөр тойрох, үнэгүй захиалга үүсгэх, brute force хийх нь зөвшөөрөлгүй бол халдлага болно. Энэ tool public risk signal илрүүлээд, owner-д authorized manual payment test хэрэгтэй хэсгийг заана.",
    unlockTitle: "Дэлгэрэнгүй тайлан нээх",
    unlockDesc: "Яг юу эвдэрсэн, хэрхэн засах, AI тайлбар — бүгдийг харах",
    unlockBtn: "QPay-аар нээх",
    unlockPrice: "9,900₮",
    unlockCreating: "Нэхэмжлэл үүсгэж байна...",
    unlockWaiting: "QPay нээж, QR уншуулна уу...",
    unlockScanAnother: "Нэхэмжлэл дуусаагүй — хаах уу?",
    detailsLocked: "Засах арга болон нотолгоог харахын тулд тайланг нээнэ үү",
    scanDone: "Шалгалт дууслаа",
    criticalFound: (n: number) => `${n} АЮУЛТ АЛДАА ИЛЭРЛЭЭ`,
    urgencyAlert: (n: number) => `⚠ АНХААР — ${n} аюулт эрсдэл илэрлээ`,
    urgencyAlertSub: "Таны дэлгүүрийн checkout болон QPay хамгаалалт одоо эрсдэлтэй байна. Засах заавар доор байна.",
    compareOld: "Мэргэжлийн аудит",
    compareOldPrice: "₮150,000",
    compareNew: "Автомат тайлан — ӨНӨӨДӨР",
    expiresLabel: "Тайлан дуусах",
    whatYouGet: ["Яг аль мөр код, юу засах", "AI тайлбар монгол хэлээр", "QPay bypass эрсдэлийн шалгалт", "Бүх алдааны засах заавар"],
    lockedHint: "🔒 Тайлан нээгдэхэд харагдана",
    paidBadge: "✓ ТАЙЛАН НЭЭГДЛЭЭ",
  },
  en: {
    badge: "E-commerce Security Lab",
    title:
      "Audit online shops, checkout, QPay, DNS, cookies, privacy, and payment risk in one scan.",
    subtitle:
      "No exploit payloads, brute force, or free-purchase attempts against live sites. It uses public evidence to tell owners what to fix.",
    url: "Website URL",
    run: "Run scan",
    scanning: "Scanning...",
    overall: "Overall safety",
    target: "Target",
    score: "Score",
    time: "Time",
    scanned: "Scanned",
    findings: "Findings",
    findingsTitle: "What is good, bad, and urgent",
    evidence: "Evidence",
    impact: "What can happen",
    fix: "Fix",
    ai: "AI review",
    aiTitle: "Plain-English owner summary",
    aiModel: "Model",
    ecommerce: "E-commerce",
    shopTitle: "Shop and payments",
    likelyShop: "Likely shop",
    checkout: "Checkout",
    cart: "Cart",
    login: "Login",
    platform: "Platform",
    payments: "Payments",
    bypassRisk: "Bypass risk",
    privacy: "Privacy",
    refund: "Refund",
    cookieConsent: "Cookie consent",
    dns: "DNS",
    emailDomain: "Email and domain",
    cert: "Certificate",
    enabled: "Enabled",
    trusted: "Trusted",
    protocol: "Protocol",
    cipher: "Cipher",
    issuer: "Issuer",
    validTo: "Valid to",
    crawlEyebrow: "Crawl",
    crawlTitle: "Checked checkout/cart/login pages",
    kindCol: "Kind",
    formsCol: "Forms",
    providersCol: "Providers",
    runtime: "Browser errors and failed requests",
    headers: "Response headers",
    noErrors: "No browser runtime errors found.",
    yes: "Yes",
    no: "No",
    unknown: "Unknown",
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
    good: "Good",
    paymentNote:
      "Note: bypassing payment, creating free orders, or brute forcing a live shop without permission is an attack. This tool flags public risk signals and points the owner to authorized manual payment tests.",
    unlockTitle: "Unlock full report",
    unlockDesc: "Exactly what's broken, how to fix it, and AI summary — everything",
    unlockBtn: "Pay with QPay",
    unlockPrice: "9,900₮",
    unlockCreating: "Creating invoice...",
    unlockWaiting: "Open QPay and scan the QR code...",
    unlockScanAnother: "Invoice not completed — close anyway?",
    detailsLocked: "Unlock the report to see evidence, impact and fix",
    scanDone: "Scan complete",
    criticalFound: (n: number) => `${n} CRITICAL ISSUE${n === 1 ? "" : "S"} FOUND`,
    urgencyAlert: (n: number) => `⚠ WARNING — ${n} critical risk${n === 1 ? "" : "s"} detected`,
    urgencyAlertSub: "Your checkout and QPay integration have exposed vulnerabilities. Fix instructions are locked below.",
    compareOld: "Professional audit",
    compareOldPrice: "₮150,000",
    compareNew: "Automated report — TODAY",
    expiresLabel: "Report expires",
    whatYouGet: ["Exact lines of code to fix", "AI summary in plain language", "QPay bypass risk check", "Fix guide for every finding"],
    lockedHint: "🔒 Visible after unlock",
    paidBadge: "✓ REPORT UNLOCKED",
  },
};

export default function Home() {
  const [language, setLanguage] = useState<Language>("mn");
  const [url, setUrl] = useState(defaultUrl);
  const [data, setData] = useState<SecurityScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isPaid, setIsPaid] = useState(false);
  const [invoiceData, setInvoiceData] = useState<InvoiceData | null>(null);
  const [isCreatingPayment, setIsCreatingPayment] = useState(false);
  const t = copy[language];

  const counts = useMemo(() => {
    const base = Object.fromEntries(severityOrder.map((severity) => [severity, 0])) as Record<
      Severity,
      number
    >;
    for (const finding of data?.findings ?? []) {
      base[finding.severity] += 1;
    }
    return base;
  }, [data]);

  useEffect(() => {
    if (!invoiceData || isPaid) return;
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`/api/payment/status?invoice_id=${invoiceData.invoiceId}`);
        const json = (await res.json()) as { paid?: boolean };
        if (json.paid) {
          setIsPaid(true);
          setInvoiceData(null);
        }
      } catch {}
    }, 3000);
    return () => clearInterval(interval);
  }, [invoiceData, isPaid]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    setData(null);
    setIsPaid(false);
    setInvoiceData(null);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url, language }),
      });

      const result = (await response.json()) as {
        data?: SecurityScanResult;
        error?: string;
      };

      if (!response.ok) {
        throw new Error(result.error || "Scan failed.");
      }

      setData(result.data ?? null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Scan failed.");
    } finally {
      setIsLoading(false);
    }
  }

  async function handleCreatePayment() {
    setIsCreatingPayment(true);
    setError(null);
    try {
      const res = await fetch("/api/payment/create", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const json = (await res.json()) as InvoiceData & { error?: string };
      if (!res.ok) throw new Error(json.error ?? "Payment creation failed");
      setInvoiceData(json);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Payment creation failed");
    } finally {
      setIsCreatingPayment(false);
    }
  }

  function handleCloseModal() {
    if (invoiceData && !isPaid) {
      if (!confirm(t.unlockScanAnother)) return;
    }
    setInvoiceData(null);
  }

  return (
    <main className="min-h-screen bg-[#0b0d10] text-slate-100">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-5 sm:px-6 lg:px-8">
        <header className="grid gap-5 border-b border-white/10 pb-5 lg:grid-cols-[1fr_390px] lg:items-end">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              <p className="font-mono text-xs uppercase text-cyan-300">{t.badge}</p>
              <div className="inline-grid grid-cols-2 overflow-hidden rounded-md border border-white/15 text-xs">
                {(["mn", "en"] as const).map((item) => (
                  <button
                    className={`px-3 py-1.5 ${language === item ? "bg-cyan-300 text-slate-950" : "bg-white/5 text-slate-300"}`}
                    key={item}
                    onClick={() => setLanguage(item)}
                    type="button"
                  >
                    {item.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
            <h1 className="max-w-5xl text-3xl font-semibold leading-tight text-white sm:text-5xl">
              {t.title}
            </h1>
            <p className="max-w-3xl text-sm leading-6 text-slate-300">{t.subtitle}</p>
          </div>

          <form onSubmit={handleSubmit} className="grid gap-2">
            <label className="text-sm text-slate-300" htmlFor="url">
              {t.url}
            </label>
            <div className="grid gap-2 sm:grid-cols-[1fr_auto] lg:grid-cols-1">
              <input
                id="url"
                value={url}
                onChange={(event) => setUrl(event.target.value)}
                className="min-h-11 rounded-md border border-white/15 bg-white px-3 text-sm text-slate-950 outline-none transition focus:border-cyan-300 focus:ring-2 focus:ring-cyan-300/20"
                placeholder="https://example.mn"
                type="text"
                required
              />
              <button
                type="submit"
                disabled={isLoading}
                className="min-h-11 rounded-md bg-cyan-300 px-5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isLoading ? t.scanning : t.run}
              </button>
            </div>
          </form>
        </header>

        <section className="rounded-md border border-amber-300/30 bg-amber-400/10 p-4 text-sm leading-6 text-amber-50">
          {t.paymentNote}
        </section>

        {error ? (
          <section className="rounded-md border border-red-400/40 bg-red-950/40 p-4 text-sm text-red-100">
            {error}
          </section>
        ) : null}

        {isLoading ? <LoadingState language={language} /> : null}

        {invoiceData ? (
          <PaymentModal
            invoice={invoiceData}
            t={t}
            onClose={handleCloseModal}
          />
        ) : null}

        {data ? (
          <div className="grid gap-5">
            {!isPaid ? (
              <section className="relative overflow-hidden rounded-xl border border-red-500/40 bg-red-950/30 p-5">
                <div className="flex items-start gap-4">
                  <span className="relative mt-0.5 flex size-3 shrink-0">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
                    <span className="relative inline-flex size-3 rounded-full bg-red-500" />
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-base font-semibold text-red-200">
                      {t.urgencyAlert(counts.critical + counts.high)}
                    </p>
                    <p className="mt-1 text-sm leading-6 text-red-300/80">{t.urgencyAlertSub}</p>
                  </div>
                  <button
                    onClick={handleCreatePayment}
                    disabled={isCreatingPayment}
                    className="shrink-0 rounded-lg bg-red-500 px-4 py-2 text-sm font-semibold text-white transition hover:bg-red-400 disabled:opacity-60"
                  >
                    {isCreatingPayment ? t.unlockCreating : `${t.unlockBtn} — ${t.unlockPrice}`}
                  </button>
                </div>
              </section>
            ) : (
              <section className="rounded-xl border border-emerald-400/30 bg-emerald-950/20 px-5 py-3">
                <p className="text-sm font-semibold text-emerald-300">{t.paidBadge}</p>
              </section>
            )}

            <section className="grid gap-4 lg:grid-cols-[300px_1fr]">
              <div className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm text-slate-400">{t.overall}</p>
                    <p className="mt-2 text-6xl font-semibold text-white">{data.grade}</p>
                  </div>
                  <ScoreRing score={data.score} />
                </div>
                <dl className="mt-5 grid gap-3 text-sm">
                  <MetricRow label={t.score} value={`${data.score}/100`} />
                  <MetricRow label="HTTP" value={data.status?.toString() ?? t.unknown} />
                  <MetricRow label={t.time} value={`${data.responseTimeMs} ms`} />
                  <MetricRow label={t.scanned} value={new Date(data.scannedAt).toLocaleString()} />
                </dl>
              </div>

              <div className="grid gap-4 rounded-lg border border-white/10 bg-white/[0.04] p-5">
                <div>
                  <p className="text-sm text-slate-400">{t.target}</p>
                  <h2 className="mt-1 break-all text-xl font-semibold text-white">
                    {data.finalUrl}
                  </h2>
                </div>

                <div className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
                  {severityOrder.map((severity) => (
                    <div
                      className="rounded-md border border-white/10 bg-black/20 p-3"
                      key={severity}
                    >
                      <p className="text-xs uppercase text-slate-500">{t[severity]}</p>
                      <p className={`mt-2 text-2xl font-semibold ${severityText(severity)}`}>
                        {counts[severity]}
                      </p>
                    </div>
                  ))}
                </div>

                <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                  {data.metrics.map((metric) => (
                    <MetricBar key={metric.label} metric={metric} language={language} />
                  ))}
                </div>
              </div>
            </section>

            <section className="grid gap-5 lg:grid-cols-[1fr_390px]">
              <div className="grid gap-3">
                <SectionTitle eyebrow={t.findings} title={t.findingsTitle} />
                {data.findings.map((finding) => (
                  <FindingCard
                    finding={finding}
                    key={finding.id}
                    t={t}
                    language={language}
                    isPaid={isPaid}
                  />
                ))}
                {!isPaid ? (
                  <UnlockBanner t={t} onUnlock={handleCreatePayment} isLoading={isCreatingPayment} scannedAt={data.scannedAt} />
                ) : null}
              </div>

              <aside className="grid content-start gap-5">
                {isPaid ? (
                  <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                    <SectionTitle eyebrow={t.ai} title={t.aiTitle} />
                    {data.aiReview ? (
                      <div className="mt-4">
                        <MarkdownText text={data.aiReview} />
                      </div>
                    ) : (
                      <p className="mt-4 text-sm leading-6 text-amber-100">
                        {data.aiError}
                      </p>
                    )}
                    {data.aiModel ? (
                      <p className="mt-4 font-mono text-xs text-slate-500">
                        {t.aiModel}: {data.aiModel}
                      </p>
                    ) : null}
                  </section>
                ) : (
                  <LockedPanel eyebrow={t.ai} title={t.aiTitle} t={t} onUnlock={handleCreatePayment} isLoading={isCreatingPayment} />
                )}

                {isPaid ? (
                  <>
                    <EcommercePanel data={data.ecommerce} t={t} />
                    <DnsPanel data={data.dns} t={t} />
                    <TlsPanel data={data.tls} t={t} />
                  </>
                ) : (
                  <>
                    <LockedPanel eyebrow={t.ecommerce} title={t.shopTitle} t={t} onUnlock={handleCreatePayment} isLoading={isCreatingPayment} />
                    <LockedPanel eyebrow={t.dns} title={t.emailDomain} t={t} onUnlock={handleCreatePayment} isLoading={isCreatingPayment} />
                    <LockedPanel eyebrow="TLS" title={t.cert} t={t} onUnlock={handleCreatePayment} isLoading={isCreatingPayment} />
                  </>
                )}
              </aside>
            </section>

            {isPaid ? (
              <section className="grid gap-5 lg:grid-cols-2">
                <PagesTable pages={data.ecommerce.pagesChecked} t={t} language={language} />
                <EvidenceList
                  items={[...data.browser.consoleErrors, ...data.browser.failedRequests]}
                  title={t.runtime}
                  emptyLabel={t.noErrors}
                />
              </section>
            ) : null}

            {isPaid ? <HeaderTable headers={data.headers} title={t.headers} /> : null}
          </div>
        ) : null}
      </div>
    </main>
  );
}

function CountdownTimer({ scannedAt }: { scannedAt: string }) {
  const expiry = useMemo(() => new Date(scannedAt).getTime() + 24 * 60 * 60 * 1000, [scannedAt]);
  const [remaining, setRemaining] = useState(() => Math.max(0, expiry - Date.now()));

  useEffect(() => {
    const id = setInterval(() => setRemaining(Math.max(0, expiry - Date.now())), 1000);
    return () => clearInterval(id);
  }, [expiry]);

  const h = Math.floor(remaining / 3600000).toString().padStart(2, "0");
  const m = Math.floor((remaining % 3600000) / 60000).toString().padStart(2, "0");
  const s = Math.floor((remaining % 60000) / 1000).toString().padStart(2, "0");

  return (
    <span className="font-mono text-red-300 tabular-nums">
      {h}:{m}:{s}
    </span>
  );
}

function UnlockBanner({
  t,
  onUnlock,
  isLoading,
  scannedAt,
}: {
  t: (typeof copy)[Language];
  onUnlock: () => void;
  isLoading: boolean;
  scannedAt: string;
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-cyan-400/20 bg-gradient-to-b from-[#0f1520] to-[#0b0d10]">
      <div className="border-b border-white/5 bg-amber-400/5 px-5 py-3">
        <p className="text-xs font-medium uppercase tracking-widest text-amber-300">
          {t.expiresLabel} → <CountdownTimer scannedAt={scannedAt} />
        </p>
      </div>

      <div className="grid gap-5 p-6 sm:grid-cols-[1fr_auto]">
        <div className="grid gap-4">
          <div className="grid gap-1">
            <div className="flex items-baseline gap-3">
              <span className="text-sm text-slate-500 line-through">{t.compareOld} {t.compareOldPrice}</span>
            </div>
            <div className="flex items-baseline gap-3">
              <span className="text-3xl font-bold text-white">{t.unlockPrice}</span>
              <span className="text-sm text-cyan-400">{t.compareNew}</span>
            </div>
          </div>

          <ul className="grid gap-1.5">
            {t.whatYouGet.map((item) => (
              <li key={item} className="flex items-center gap-2 text-sm text-slate-300">
                <svg className="size-4 shrink-0 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                </svg>
                {item}
              </li>
            ))}
          </ul>
        </div>

        <div className="flex items-center sm:items-end">
          <button
            onClick={onUnlock}
            disabled={isLoading}
            className="group relative w-full overflow-hidden rounded-xl bg-cyan-300 px-8 py-3.5 text-base font-bold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60 sm:w-auto"
          >
            <span className="relative z-10">
              {isLoading ? t.unlockCreating : `${t.unlockBtn} — ${t.unlockPrice}`}
            </span>
            <span className="absolute inset-0 -translate-x-full bg-white/20 transition-transform duration-300 group-hover:translate-x-full" />
          </button>
        </div>
      </div>
    </div>
  );
}

function LockedPanel({
  eyebrow,
  title,
  t,
  onUnlock,
  isLoading,
}: {
  eyebrow: string;
  title: string;
  t: (typeof copy)[Language];
  onUnlock: () => void;
  isLoading: boolean;
}) {
  return (
    <section className="relative overflow-hidden rounded-lg border border-white/10 bg-white/[0.04]">
      <div className="p-5">
        <SectionTitle eyebrow={eyebrow} title={title} />
        <div className="mt-4 grid gap-3 blur-md opacity-15 pointer-events-none select-none" aria-hidden>
          {[92, 68, 80, 55].map((w, i) => (
            <div key={i} className="flex items-center gap-3">
              <div className="h-4 w-28 rounded bg-white/10" />
              <div className="h-4 rounded bg-white/15" style={{ width: `${w}%` }} />
            </div>
          ))}
        </div>
      </div>
      <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 bg-[#0b0d10]/60 backdrop-blur-[2px]">
        <div className="rounded-full border border-white/10 bg-white/5 p-3">
          <svg className="size-5 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 10-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 002.25-2.25v-6.75a2.25 2.25 0 00-2.25-2.25H6.75a2.25 2.25 0 00-2.25 2.25v6.75a2.25 2.25 0 002.25 2.25z" />
          </svg>
        </div>
        <p className="text-xs text-slate-500">{t.lockedHint}</p>
        <button
          onClick={onUnlock}
          disabled={isLoading}
          className="rounded-lg bg-cyan-300 px-5 py-2 text-sm font-bold text-slate-950 transition hover:bg-cyan-200 disabled:opacity-60"
        >
          {isLoading ? t.unlockCreating : `${t.unlockBtn} — ${t.unlockPrice}`}
        </button>
      </div>
    </section>
  );
}

function PaymentModal({
  invoice,
  t,
  onClose,
}: {
  invoice: InvoiceData;
  t: (typeof copy)[Language];
  onClose: () => void;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4 backdrop-blur-sm">
      <div className="w-full max-w-sm rounded-2xl border border-white/10 bg-[#0f1117] p-6 shadow-2xl">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="font-mono text-xs uppercase text-cyan-300">{t.unlockTitle}</p>
            <p className="mt-1 text-3xl font-bold text-white">{invoice.amount.toLocaleString()}₮</p>
            <p className="text-xs text-slate-500 line-through">{t.compareOldPrice}</p>
          </div>
          <button
            onClick={onClose}
            className="rounded-md p-1.5 text-slate-400 transition hover:bg-white/10 hover:text-white"
          >
            <svg className="size-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {invoice.qrImage ? (
          <div className="mt-5 flex flex-col items-center gap-3">
            <div className="rounded-xl bg-white p-3 shadow-[0_0_30px_rgba(103,232,249,0.15)]">
              <img
                src={invoice.qrImage}
                alt="QPay QR code"
                className="size-48"
              />
            </div>
            <p className="text-center text-xs text-slate-500">QPay app нээж, QR уншуулна уу</p>
          </div>
        ) : null}

        <div className="mt-3 flex items-center justify-center gap-2">
          <span className="relative flex size-2">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-cyan-400 opacity-75" />
            <span className="relative inline-flex size-2 rounded-full bg-cyan-400" />
          </span>
          <p className="text-sm text-cyan-300">{t.unlockWaiting}</p>
        </div>

        {invoice.urls?.length ? (
          <div className="mt-4 grid gap-2">
            <p className="text-xs uppercase text-slate-500">Банкны аппаар нэвтрэх</p>
            {invoice.urls.slice(0, 4).map((bank) => (
              <a
                key={bank.name}
                href={bank.deeplink || bank.link}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-3 rounded-lg border border-white/10 bg-white/5 px-3 py-2.5 text-sm text-slate-200 transition hover:bg-white/10"
              >
                {bank.logo ? (
                  <img src={bank.logo} alt={bank.name} className="size-6 rounded object-contain" />
                ) : null}
                <span>{bank.name}</span>
                <svg className="ml-auto size-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25" />
                </svg>
              </a>
            ))}
          </div>
        ) : null}
      </div>
    </div>
  );
}

function LoadingState({ language }: { language: Language }) {
  const labels =
    language === "mn"
      ? ["Headers/TLS шалгаж байна", "Checkout/cart хайж байна", "DNS ба QPay signal уншиж байна"]
      : ["Checking headers/TLS", "Finding checkout/cart", "Reading DNS and QPay signals"];

  return (
    <section className="grid gap-4 rounded-lg border border-white/10 bg-white/[0.04] p-5 md:grid-cols-3">
      {labels.map((label) => (
        <div className="h-28 animate-pulse rounded-md bg-white/10 p-4" key={label}>
          <p className="text-sm text-slate-300">{label}</p>
        </div>
      ))}
    </section>
  );
}

function ScoreRing({ score }: { score: number }) {
  return (
    <div
      className="grid size-24 place-items-center rounded-full"
      style={{
        background: `conic-gradient(#67e8f9 ${score * 3.6}deg, rgba(255,255,255,0.1) 0deg)`,
      }}
    >
      <div className="grid size-16 place-items-center rounded-full bg-[#0b0d10]">
        <span className="font-mono text-lg font-semibold">{score}</span>
      </div>
    </div>
  );
}

function MetricBar({ metric, language }: { metric: Metric; language: Language }) {
  const label = METRIC_LABELS[language][metric.label] ?? metric.label;
  return (
    <div className="rounded-md border border-white/10 bg-black/20 p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium text-white">{label}</p>
        <p className="font-mono text-sm text-slate-300">{metric.score}</p>
      </div>
      <div className="mt-3 h-2 overflow-hidden rounded-full bg-white/10">
        <div
          className={`h-full rounded-full ${scoreColor(metric.score)}`}
          style={{ width: `${metric.score}%` }}
        />
      </div>
      <p className="mt-3 text-xs leading-5 text-slate-400">{metric.summary}</p>
    </div>
  );
}

function FindingCard({
  finding,
  t,
  language,
  isPaid,
}: {
  finding: Finding;
  t: (typeof copy)[Language];
  language: Language;
  isPaid: boolean;
}) {
  const categoryLabel = CATEGORY_LABELS[language][finding.category] ?? finding.category;
  return (
    <article className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs uppercase text-slate-500">{categoryLabel}</p>
          <h3 className="mt-1 text-lg font-semibold text-white">{finding.title}</h3>
        </div>
        <span
          className={`rounded px-2 py-1 font-mono text-xs uppercase ${severityBadge(
            finding.severity,
          )}`}
        >
          {t[finding.severity]}
        </span>
      </div>
      {isPaid ? (
        <div className="mt-4 grid gap-4 md:grid-cols-3">
          <FindingBlock label={t.evidence} text={finding.evidence} />
          <FindingBlock label={t.impact} text={finding.impact} />
          <FindingBlock label={t.fix} text={finding.recommendation} />
        </div>
      ) : (
        <div className="relative mt-4 select-none">
          <div className="grid gap-4 blur-md opacity-20 pointer-events-none md:grid-cols-3" aria-hidden>
            <FindingBlock label={t.evidence} text={finding.evidence} />
            <FindingBlock label={t.impact} text={finding.impact} />
            <FindingBlock label={t.fix} text={finding.recommendation} />
          </div>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="rounded-full border border-white/10 bg-[#0b0d10]/80 px-3 py-1 font-mono text-xs text-slate-500">
              {t.lockedHint}
            </span>
          </div>
        </div>
      )}
    </article>
  );
}

function FindingBlock({ label, text }: { label: string; text: string }) {
  const hasLines = text.includes("\n");
  return (
    <div>
      <p className="text-xs uppercase text-slate-500">{label}</p>
      {hasLines ? (
        <div className="mt-2 space-y-1">
          {text.split("\n").map((line, i) => {
            const isCode =
              line.startsWith("  ") ||
              line.startsWith("<script") ||
              /^[a-zA-Z_]+\s*[\({]/.test(line.trim()) ||
              line.trim().startsWith("//") ||
              line.trim().startsWith("?") ||
              line.trim().startsWith("https://");
            if (line.trim() === "") return <div key={i} className="h-1" />;
            return (
              <p
                key={i}
                className={
                  isCode
                    ? "break-all font-mono text-xs leading-5 text-cyan-200"
                    : "break-words text-sm leading-6 text-slate-300"
                }
              >
                {line}
              </p>
            );
          })}
        </div>
      ) : (
        <p className="mt-2 break-words text-sm leading-6 text-slate-300">{text}</p>
      )}
    </div>
  );
}

function MarkdownText({ text }: { text: string }) {
  const lines = text.split("\n");
  return (
    <div className="space-y-1">
      {lines.map((line, i) => {
        if (line.startsWith("### ")) {
          return (
            <h3 key={i} className="mt-4 text-sm font-semibold text-white first:mt-0">
              {inlineBold(line.slice(4))}
            </h3>
          );
        }
        if (line.startsWith("## ")) {
          return (
            <h2 key={i} className="mt-4 text-base font-semibold text-white first:mt-0">
              {inlineBold(line.slice(3))}
            </h2>
          );
        }
        if (line === "---") {
          return <hr key={i} className="my-3 border-white/10" />;
        }
        if (line.trim() === "") {
          return <div key={i} className="h-2" />;
        }
        const isBullet = /^[-*]\s/.test(line);
        const content = isBullet ? line.replace(/^[-*]\s/, "") : line;
        return (
          <p
            key={i}
            className={`text-sm leading-6 text-slate-200 ${isBullet ? "pl-4 before:mr-2 before:content-['•']" : ""}`}
          >
            {inlineBold(content)}
          </p>
        );
      })}
    </div>
  );
}

function inlineBold(text: string) {
  const parts = text.split(/(\*\*[^*]+\*\*)/);
  return parts.map((part, i) =>
    part.startsWith("**") ? (
      <strong key={i} className="font-semibold text-white">
        {part.slice(2, -2)}
      </strong>
    ) : (
      part
    ),
  );
}

function EcommercePanel({
  data,
  t,
}: {
  data: EcommerceSignal;
  t: (typeof copy)[Language];
}) {
  const yn = (value: boolean) => (value ? t.yes : t.no);

  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle eyebrow={t.ecommerce} title={t.shopTitle} />
      <dl className="mt-4 grid gap-3 text-sm">
        <MetricRow label={t.likelyShop} value={yn(data.isLikelyEcommerce)} />
        <MetricRow label="QPay" value={yn(data.qpayDetected)} />
        <MetricRow label={t.checkout} value={data.checkoutPages.toString()} />
        <MetricRow label={t.cart} value={data.cartPages.toString()} />
        <MetricRow label={t.login} value={data.loginPages.toString()} />
        <MetricRow label={t.platform} value={data.platform.join(", ") || "-"} />
        <MetricRow label={t.payments} value={data.paymentProviders.join(", ") || "-"} />
        <MetricRow
          label={t.bypassRisk}
          value={`${data.paymentBypassRiskScore}/100 (${data.paymentBypassRiskLevel})`}
        />
        <MetricRow label={t.privacy} value={yn(data.policies.privacy)} />
        <MetricRow label={t.refund} value={yn(data.policies.refund)} />
        <MetricRow label={t.cookieConsent} value={yn(data.cookieConsent)} />
      </dl>
      {data.riskyClientPaymentSignals.length ? (
        <div className="mt-4 rounded-md border border-orange-300/30 bg-orange-400/10 p-3">
          <p className="text-xs uppercase text-orange-100">Payment bypass signals</p>
          <ul className="mt-2 grid gap-2 text-xs leading-5 text-orange-50">
            {data.riskyClientPaymentSignals.map((signal) => (
              <li className="break-words" key={signal}>
                {signal}
              </li>
            ))}
          </ul>
        </div>
      ) : null}
    </section>
  );
}

function DnsPanel({ data, t }: { data: DnsSignal; t: (typeof copy)[Language] }) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle eyebrow={t.dns} title={t.emailDomain} />
      <dl className="mt-4 grid gap-3 text-sm">
        <MetricRow label="MX" value={data.mx.join(", ") || "-"} />
        <MetricRow label="SPF" value={data.spf ?? "-"} />
        <MetricRow label="DMARC" value={data.dmarc ?? "-"} />
        <MetricRow label="CAA" value={data.caa.join(", ") || "-"} />
      </dl>
    </section>
  );
}

function TlsPanel({ data, t }: { data: TlsSignal; t: (typeof copy)[Language] }) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle eyebrow="TLS" title={t.cert} />
      <dl className="mt-4 grid gap-3 text-sm">
        <MetricRow label={t.enabled} value={data.enabled ? t.yes : t.no} />
        <MetricRow
          label={t.trusted}
          value={data.authorized === null ? t.unknown : data.authorized ? t.yes : t.no}
        />
        <MetricRow label={t.protocol} value={data.protocol ?? "-"} />
        <MetricRow label={t.cipher} value={data.cipher ?? "-"} />
        <MetricRow label={t.issuer} value={data.issuer ?? "-"} />
        <MetricRow label={t.validTo} value={data.validTo ?? "-"} />
      </dl>
    </section>
  );
}

function PagesTable({
  pages,
  t,
  language,
}: {
  pages: PageSignal[];
  t: (typeof copy)[Language];
  language: Language;
}) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle eyebrow={t.crawlEyebrow} title={t.crawlTitle} />
      <div className="mt-4 max-h-[460px] overflow-auto rounded-md border border-white/10">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="bg-black/30 text-slate-400">
            <tr>
              <th className="p-3">{t.kindCol}</th>
              <th className="p-3">HTTPS</th>
              <th className="p-3">{t.formsCol}</th>
              <th className="p-3">{t.providersCol}</th>
              <th className="p-3">URL</th>
            </tr>
          </thead>
          <tbody>
            {pages.map((page) => (
              <tr className="border-t border-white/10" key={page.url}>
                <td className="p-3 text-slate-200">{KIND_LABELS[language][page.kind]}</td>
                <td className="p-3">{page.https ? t.yes : t.no}</td>
                <td className="p-3">{page.forms}</td>
                <td className="p-3">{page.providers.join(", ") || "-"}</td>
                <td className="break-all p-3 text-slate-400">{page.url}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function EvidenceList({
  title,
  items,
  emptyLabel,
}: {
  title: string;
  items: string[];
  emptyLabel: string;
}) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle eyebrow="Evidence" title={title} />
      {items.length ? (
        <ul className="mt-4 grid gap-2">
          {items.map((item, index) => (
            <li
              className="break-all rounded-md border border-white/10 bg-black/20 p-3 font-mono text-xs leading-5 text-slate-300"
              key={`${item}-${index}`}
            >
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-4 text-sm text-slate-400">{emptyLabel}</p>
      )}
    </section>
  );
}

function HeaderTable({ headers, title }: { headers: Record<string, string>; title: string }) {
  const rows = Object.entries(headers).sort(([a], [b]) => a.localeCompare(b));

  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle eyebrow="HTTP" title={title} />
      <div className="mt-4 max-h-[460px] overflow-auto rounded-md border border-white/10">
        <table className="w-full border-collapse text-left text-sm">
          <tbody>
            {rows.map(([name, value]) => (
              <tr className="border-b border-white/10 last:border-0" key={name}>
                <th className="w-1/3 p-3 align-top font-mono text-xs text-cyan-200">{name}</th>
                <td className="break-all p-3 text-slate-300">{value}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function SectionTitle({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div>
      <p className="font-mono text-xs uppercase text-cyan-300">{eyebrow}</p>
      <h2 className="mt-1 text-xl font-semibold text-white">{title}</h2>
    </div>
  );
}

function MetricRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[140px_1fr] gap-3 border-b border-white/10 pb-2 last:border-0 last:pb-0">
      <dt className="text-slate-500">{label}</dt>
      <dd className="break-words text-slate-200">{value}</dd>
    </div>
  );
}

function scoreColor(score: number) {
  if (score >= 80) return "bg-emerald-300";
  if (score >= 60) return "bg-amber-300";
  return "bg-red-400";
}

function severityText(severity: Severity) {
  switch (severity) {
    case "critical":
      return "text-red-300";
    case "high":
      return "text-orange-300";
    case "medium":
      return "text-amber-300";
    case "low":
      return "text-cyan-200";
    case "good":
      return "text-emerald-300";
    default:
      return "text-slate-300";
  }
}

function severityBadge(severity: Severity) {
  switch (severity) {
    case "critical":
      return "border border-red-300/40 bg-red-400/15 text-red-200";
    case "high":
      return "border border-orange-300/40 bg-orange-400/15 text-orange-200";
    case "medium":
      return "border border-amber-300/40 bg-amber-400/15 text-amber-100";
    case "low":
      return "border border-cyan-300/40 bg-cyan-400/15 text-cyan-100";
    case "good":
      return "border border-emerald-300/40 bg-emerald-400/15 text-emerald-100";
    default:
      return "border border-slate-300/40 bg-slate-400/15 text-slate-100";
  }
}
