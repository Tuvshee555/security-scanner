"use client";

import { FormEvent, useMemo, useState } from "react";

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

const defaultUrl = "https://example.com";
const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info", "good"];

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
    findings: "Олдсон зүйлс",
    findingsTitle: "Юу сайн, юу муу, юу яаралтай вэ",
    evidence: "Нотолгоо",
    impact: "Юу болж магадгүй",
    fix: "Засах арга",
    ai: "AI тайлбар",
    aiTitle: "Худалдагчид ойлгомжтой дүгнэлт",
    ecommerce: "Дэлгүүрийн шалгалт",
    dns: "DNS / Имэйл итгэлцэл",
    pages: "Шалгасан e-commerce хуудсууд",
    runtime: "Browser алдаа ба failed request",
    headers: "Response headers",
    yes: "Тийм",
    no: "Үгүй",
    unknown: "Мэдэгдэхгүй",
    paymentNote:
      "Тайлбар: live дэлгүүр дээр төлбөр тойрох, үнэгүй захиалга үүсгэх, brute force хийх нь зөвшөөрөлгүй бол халдлага болно. Энэ tool public risk signal илрүүлээд, owner-д authorized manual payment test хэрэгтэй хэсгийг заана.",
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
    findings: "Findings",
    findingsTitle: "What is good, bad, and urgent",
    evidence: "Evidence",
    impact: "What can happen",
    fix: "Fix",
    ai: "AI review",
    aiTitle: "Plain-English owner summary",
    ecommerce: "Shop audit",
    dns: "DNS / Email trust",
    pages: "E-commerce pages checked",
    runtime: "Browser errors and failed requests",
    headers: "Response headers",
    yes: "Yes",
    no: "No",
    unknown: "Unknown",
    paymentNote:
      "Note: bypassing payment, creating free orders, or brute forcing a live shop without permission is an attack. This tool flags public risk signals and points the owner to authorized manual payment tests.",
  },
};

export default function Home() {
  const [language, setLanguage] = useState<Language>("mn");
  const [url, setUrl] = useState(defaultUrl);
  const [data, setData] = useState<SecurityScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
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

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    setData(null);

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

        {data ? (
          <div className="grid gap-5">
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
                  <MetricRow label="Score" value={`${data.score}/100`} />
                  <MetricRow label="HTTP" value={data.status?.toString() ?? t.unknown} />
                  <MetricRow label="Time" value={`${data.responseTimeMs} ms`} />
                  <MetricRow label="Scanned" value={new Date(data.scannedAt).toLocaleString()} />
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
                      <p className="text-xs uppercase text-slate-500">{severity}</p>
                      <p className={`mt-2 text-2xl font-semibold ${severityText(severity)}`}>
                        {counts[severity]}
                      </p>
                    </div>
                  ))}
                </div>

                <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                  {data.metrics.map((metric) => (
                    <MetricBar key={metric.label} metric={metric} />
                  ))}
                </div>
              </div>
            </section>

            <section className="grid gap-5 lg:grid-cols-[1fr_390px]">
              <div className="grid gap-3">
                <SectionTitle eyebrow={t.findings} title={t.findingsTitle} />
                {data.findings.map((finding) => (
                  <FindingCard finding={finding} key={finding.id} t={t} />
                ))}
              </div>

              <aside className="grid content-start gap-5">
                <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
                  <SectionTitle eyebrow={t.ai} title={t.aiTitle} />
                  {data.aiReview ? (
                    <div className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-200">
                      {data.aiReview}
                    </div>
                  ) : (
                    <p className="mt-4 text-sm leading-6 text-amber-100">
                      {data.aiError}
                    </p>
                  )}
                  {data.aiModel ? (
                    <p className="mt-4 font-mono text-xs text-slate-500">
                      Model: {data.aiModel}
                    </p>
                  ) : null}
                </section>

                <EcommercePanel data={data.ecommerce} language={language} />
                <DnsPanel data={data.dns} language={language} />
                <TlsPanel data={data.tls} language={language} />
              </aside>
            </section>

            <section className="grid gap-5 lg:grid-cols-2">
              <PagesTable pages={data.ecommerce.pagesChecked} language={language} />
              <EvidenceList
                items={[...data.browser.consoleErrors, ...data.browser.failedRequests]}
                title={t.runtime}
              />
            </section>

            <HeaderTable headers={data.headers} title={t.headers} />
          </div>
        ) : null}
      </div>
    </main>
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

function MetricBar({ metric }: { metric: Metric }) {
  return (
    <div className="rounded-md border border-white/10 bg-black/20 p-3">
      <div className="flex items-center justify-between gap-2">
        <p className="text-sm font-medium text-white">{metric.label}</p>
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
}: {
  finding: Finding;
  t: (typeof copy)[Language];
}) {
  return (
    <article className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="text-xs uppercase text-slate-500">{finding.category}</p>
          <h3 className="mt-1 text-lg font-semibold text-white">{finding.title}</h3>
        </div>
        <span
          className={`rounded px-2 py-1 font-mono text-xs uppercase ${severityBadge(
            finding.severity,
          )}`}
        >
          {finding.severity}
        </span>
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-3">
        <FindingBlock label={t.evidence} text={finding.evidence} />
        <FindingBlock label={t.impact} text={finding.impact} />
        <FindingBlock label={t.fix} text={finding.recommendation} />
      </div>
    </article>
  );
}

function FindingBlock({ label, text }: { label: string; text: string }) {
  return (
    <div>
      <p className="text-xs uppercase text-slate-500">{label}</p>
      <p className="mt-2 break-words text-sm leading-6 text-slate-300">{text}</p>
    </div>
  );
}

function EcommercePanel({
  data,
  language,
}: {
  data: EcommerceSignal;
  language: Language;
}) {
  const yn = (value: boolean) =>
    value ? (language === "mn" ? "Тийм" : "Yes") : language === "mn" ? "Үгүй" : "No";

  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle
        eyebrow={language === "mn" ? "E-commerce" : "E-commerce"}
        title={language === "mn" ? "Дэлгүүр ба төлбөр" : "Shop and payments"}
      />
      <dl className="mt-4 grid gap-3 text-sm">
        <MetricRow label={language === "mn" ? "Дэлгүүр мөн үү" : "Likely shop"} value={yn(data.isLikelyEcommerce)} />
        <MetricRow label="QPay" value={yn(data.qpayDetected)} />
        <MetricRow label={language === "mn" ? "Checkout" : "Checkout"} value={data.checkoutPages.toString()} />
        <MetricRow label={language === "mn" ? "Cart" : "Cart"} value={data.cartPages.toString()} />
        <MetricRow label={language === "mn" ? "Login" : "Login"} value={data.loginPages.toString()} />
        <MetricRow label={language === "mn" ? "Platform" : "Platform"} value={data.platform.join(", ") || "-"} />
        <MetricRow label={language === "mn" ? "Төлбөр" : "Payments"} value={data.paymentProviders.join(", ") || "-"} />
        <MetricRow
          label="Bypass risk"
          value={`${data.paymentBypassRiskScore}/100 (${data.paymentBypassRiskLevel})`}
        />
        <MetricRow label={language === "mn" ? "Privacy" : "Privacy"} value={yn(data.policies.privacy)} />
        <MetricRow label={language === "mn" ? "Refund" : "Refund"} value={yn(data.policies.refund)} />
        <MetricRow label={language === "mn" ? "Cookie consent" : "Cookie consent"} value={yn(data.cookieConsent)} />
      </dl>
      {data.riskyClientPaymentSignals.length ? (
        <div className="mt-4 rounded-md border border-orange-300/30 bg-orange-400/10 p-3">
          <p className="text-xs uppercase text-orange-100">
            Payment bypass signals
          </p>
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

function DnsPanel({ data, language }: { data: DnsSignal; language: Language }) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle eyebrow="DNS" title={language === "mn" ? "Имэйл ба домэйн" : "Email and domain"} />
      <dl className="mt-4 grid gap-3 text-sm">
        <MetricRow label="MX" value={data.mx.join(", ") || "-"} />
        <MetricRow label="SPF" value={data.spf ?? "-"} />
        <MetricRow label="DMARC" value={data.dmarc ?? "-"} />
        <MetricRow label="CAA" value={data.caa.join(", ") || "-"} />
      </dl>
    </section>
  );
}

function TlsPanel({ data, language }: { data: TlsSignal; language: Language }) {
  const yes = language === "mn" ? "Тийм" : "Yes";
  const no = language === "mn" ? "Үгүй" : "No";
  const unknown = language === "mn" ? "Мэдэгдэхгүй" : "Unknown";

  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle eyebrow="TLS" title={language === "mn" ? "Сертификат" : "Certificate"} />
      <dl className="mt-4 grid gap-3 text-sm">
        <MetricRow label="Enabled" value={data.enabled ? yes : no} />
        <MetricRow
          label="Trusted"
          value={data.authorized === null ? unknown : data.authorized ? yes : no}
        />
        <MetricRow label="Protocol" value={data.protocol ?? "-"} />
        <MetricRow label="Cipher" value={data.cipher ?? "-"} />
        <MetricRow label="Issuer" value={data.issuer ?? "-"} />
        <MetricRow label="Valid to" value={data.validTo ?? "-"} />
      </dl>
    </section>
  );
}

function PagesTable({ pages, language }: { pages: PageSignal[]; language: Language }) {
  return (
    <section className="rounded-lg border border-white/10 bg-white/[0.04] p-5">
      <SectionTitle
        eyebrow={language === "mn" ? "Crawl" : "Crawl"}
        title={language === "mn" ? "Шалгасан checkout/cart/login хуудсууд" : "Checked checkout/cart/login pages"}
      />
      <div className="mt-4 max-h-[460px] overflow-auto rounded-md border border-white/10">
        <table className="w-full border-collapse text-left text-xs">
          <thead className="bg-black/30 text-slate-400">
            <tr>
              <th className="p-3">Kind</th>
              <th className="p-3">HTTPS</th>
              <th className="p-3">Forms</th>
              <th className="p-3">Providers</th>
              <th className="p-3">URL</th>
            </tr>
          </thead>
          <tbody>
            {pages.map((page) => (
              <tr className="border-t border-white/10" key={page.url}>
                <td className="p-3 text-slate-200">{page.kind}</td>
                <td className="p-3">{page.https ? "yes" : "no"}</td>
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

function EvidenceList({ title, items }: { title: string; items: string[] }) {
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
        <p className="mt-4 text-sm text-slate-400">No browser runtime errors found.</p>
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
                <th className="w-1/3 p-3 align-top font-mono text-xs text-cyan-200">
                  {name}
                </th>
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
    <div className="grid grid-cols-[120px_1fr] gap-3 border-b border-white/10 pb-2 last:border-0 last:pb-0">
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
