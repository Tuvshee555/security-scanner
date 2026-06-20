import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import puppeteer from "puppeteer";

type Severity = "critical" | "high" | "medium" | "low" | "info" | "good";
export type ReportLanguage = "mn" | "en";

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  category: string;
  evidence: string;
  impact: string;
  recommendation: string;
}

export interface Metric {
  label: string;
  score: number;
  weight: number;
  summary: string;
}

export interface BrowserSignal {
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

export interface TlsSignal {
  enabled: boolean;
  authorized: boolean | null;
  protocol: string | null;
  cipher: string | null;
  validFrom: string | null;
  validTo: string | null;
  issuer: string | null;
  subject: string | null;
}

export interface DnsSignal {
  mx: string[];
  spf: string | null;
  dmarc: string | null;
  caa: string[];
}

export interface PageSignal {
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

export interface EcommerceSignal {
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

export interface SecurityScanResult {
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

const SECURITY_HEADERS = [
  "content-security-policy",
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
];

const KEY_PATHS = [
  "/cart",
  "/checkout",
  "/login",
  "/account",
  "/products",
  "/shop",
  "/privacy",
  "/privacy-policy",
  "/terms",
  "/terms-and-conditions",
  "/refund",
  "/refund-policy",
  "/contact",
];

const PROVIDERS: Record<string, RegExp> = {
  QPay: /\bqpay\b|qpay\.mn|qpaywallet|qpaymerchant|qpay_payment|deeplink/i,
  Stripe: /stripe\.com|stripe\.js|pk_live_|pk_test_|checkout\.stripe/i,
  PayPal: /paypal\.com|paypalobjects\.com|braintree/i,
  Shopify: /cdn\.shopify\.com|myshopify\.com|Shopify\.|\/cart\/add/i,
  WooCommerce: /woocommerce|wc-ajax|wp-content\/plugins\/woocommerce/i,
  "SocialPay": /socialpay/i,
  "Khan Bank": /khanbank|qpay|cardcenter/i,
  MonPay: /monpay/i,
  "2Checkout": /2checkout|verifone/i,
  Square: /squareup\.com|squarecdn/i,
};

const PLATFORM_HINTS: Record<string, RegExp> = {
  Shopify: /cdn\.shopify\.com|myshopify\.com|Shopify\.|\/cart\/add/i,
  WooCommerce: /woocommerce|wc-ajax|wp-content\/plugins\/woocommerce/i,
  Magento: /magento|mage\/|x-magento/i,
  BigCommerce: /bigcommerce|stencil-utils/i,
  Wix: /wixstatic\.com|wix\.com/i,
  Squarespace: /squarespace\.com|static1\.squarespace/i,
};

const GEMINI_MODEL = "gemini-2.5-flash";

export function normalizePublicUrl(input: string) {
  const withProtocol = /^[a-z][a-z\d+\-.]*:\/\//i.test(input)
    ? input
    : `https://${input}`;
  const url = new URL(withProtocol);

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs can be scanned.");
  }

  url.hash = "";
  return url;
}

export async function assertPublicTarget(url: URL) {
  if (
    ["localhost", "0.0.0.0"].includes(url.hostname.toLowerCase()) ||
    url.hostname.endsWith(".local")
  ) {
    throw new Error("Local and private network targets are blocked.");
  }

  const records = await dns.lookup(url.hostname, { all: true });
  if (!records.length) {
    throw new Error("The hostname could not be resolved.");
  }

  const privateAddress = records.find((record) => isPrivateAddress(record.address));
  if (privateAddress) {
    throw new Error("This hostname resolves to a private network address.");
  }
}

export async function scanWebsite(
  url: URL,
  language: ReportLanguage = "mn",
): Promise<SecurityScanResult> {
  const started = Date.now();
  const [responseSignal, tlsSignal, browserSignal, dnsSignal] = await Promise.all([
    fetchHeadersAndHtml(url),
    inspectTls(url),
    inspectInBrowser(url),
    inspectDns(url.hostname),
  ]);

  const ecommerce = await inspectEcommerce(url, responseSignal.body);
  const findings = buildFindings(
    responseSignal,
    tlsSignal,
    browserSignal,
    dnsSignal,
    ecommerce,
  );
  const metrics = buildMetrics(
    findings,
    responseSignal,
    tlsSignal,
    browserSignal,
    dnsSignal,
    ecommerce,
  );
  const score = Math.max(
    0,
    Math.round(
      metrics.reduce((total, metric) => total + metric.score * metric.weight, 0) /
        metrics.reduce((total, metric) => total + metric.weight, 0),
    ),
  );

  const ai = await createAiReview(
    {
      url: url.toString(),
      finalUrl: responseSignal.finalUrl || browserSignal.finalUrl,
      status: responseSignal.status,
      tls: tlsSignal,
      dns: dnsSignal,
      metrics,
      findings,
      browser: browserSignal,
      ecommerce,
      note:
        "Active payment bypass, free purchase attempts, brute force, and exploit payloads were not performed. This is a safe public e-commerce posture review.",
    },
    language,
  );

  return {
    inputUrl: url.toString(),
    finalUrl: responseSignal.finalUrl || browserSignal.finalUrl,
    scannedAt: new Date().toISOString(),
    status: responseSignal.status,
    responseTimeMs: Date.now() - started,
    contentType: responseSignal.headers["content-type"] ?? null,
    headers: responseSignal.headers,
    tls: tlsSignal,
    dns: dnsSignal,
    browser: browserSignal,
    ecommerce,
    metrics,
    findings,
    score,
    grade: scoreToGrade(score),
    aiReview: ai.review,
    aiModel: ai.model,
    aiError: ai.error,
  };
}

async function fetchHeadersAndHtml(url: URL) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);

  try {
    const response = await fetch(url, {
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 SecurityReviewBot/1.0 (+https://example.invalid/security-review)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    const headers = Object.fromEntries(
      Array.from(response.headers.entries()).map(([key, value]) => [
        key.toLowerCase(),
        value,
      ]),
    );

    return {
      finalUrl: response.url,
      status: response.status,
      headers,
      body: await response.text().catch(() => ""),
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function inspectTls(url: URL): Promise<TlsSignal> {
  if (url.protocol !== "https:") {
    return emptyTls(false);
  }

  const port = Number(url.port || 443);

  return await new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: url.hostname,
        port,
        servername: url.hostname,
        rejectUnauthorized: false,
        timeout: 15000,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const cipher = socket.getCipher();
        resolve({
          enabled: true,
          authorized: socket.authorized,
          protocol: socket.getProtocol(),
          cipher: cipher?.name ?? null,
          validFrom: cert.valid_from ?? null,
          validTo: cert.valid_to ?? null,
          issuer: cert.issuer?.O ?? cert.issuer?.CN ?? null,
          subject: cert.subject?.CN ?? null,
        });
        socket.end();
      },
    );

    socket.on("timeout", () => {
      socket.destroy();
      resolve(emptyTls(true));
    });
    socket.on("error", () => resolve(emptyTls(true)));
  });
}

async function inspectDns(hostname: string): Promise<DnsSignal> {
  const root = hostname.replace(/^www\./i, "");
  const [mx, txt, dmarcTxt, caa] = await Promise.all([
    dns.resolveMx(root).catch(() => []),
    dns.resolveTxt(root).catch(() => []),
    dns.resolveTxt(`_dmarc.${root}`).catch(() => []),
    dns.resolveCaa(root).catch(() => []),
  ]);

  return {
    mx: mx.map((record) => `${record.exchange} (${record.priority})`),
    spf: txt.flat().find((entry) => entry.toLowerCase().startsWith("v=spf1")) ?? null,
    dmarc:
      dmarcTxt
        .flat()
        .find((entry) => entry.toLowerCase().startsWith("v=dmarc1")) ?? null,
    caa: caa.map((record) => {
      const value = record.issue ?? record.issuewild ?? record.iodef ?? "";
      return `${record.critical ? "critical " : ""}${value}`;
    }),
  };
}

async function inspectInBrowser(url: URL): Promise<BrowserSignal> {
  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });

  try {
    const page = await browser.newPage();
    const consoleErrors: string[] = [];
    const failedRequests: string[] = [];

    await page.setViewport({ width: 1366, height: 900 });
    await page.setUserAgent(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
    );

    page.on("console", (message) => {
      if (message.type() === "error") {
        consoleErrors.push(message.text().slice(0, 240));
      }
    });

    page.on("requestfailed", (request) => {
      const errorText = request.failure()?.errorText ?? "failed";
      const reqUrl = request.url();
      // Next.js RSC prefetch aborts are expected client-side behaviour, not real errors
      if (errorText === "net::ERR_ABORTED" && /[?&]_rsc=/.test(reqUrl)) return;
      failedRequests.push(`${errorText}: ${reqUrl}`.slice(0, 240));
    });

    await page.goto(url.toString(), {
      waitUntil: "networkidle2",
      timeout: 30000,
    });

    return await page.evaluate(() => {
      const scripts = Array.from(document.scripts);
      const finalUrl = location.href;
      const securePage = location.protocol === "https:";
      const mixedContent = Array.from(
        document.querySelectorAll<HTMLImageElement | HTMLScriptElement | HTMLLinkElement>(
          "script[src], img[src], link[href]",
        ),
      )
        .map((element) => element.getAttribute("src") ?? element.getAttribute("href"))
        .filter((asset): asset is string => Boolean(asset))
        .filter((asset) => securePage && asset.startsWith("http://"))
        .slice(0, 12);

      return {
        finalUrl,
        title: document.title || null,
        forms: document.forms.length,
        passwordInputs: document.querySelectorAll('input[type="password"]').length,
        externalScripts: scripts.filter((script) => script.src).length,
        inlineScripts: scripts.filter((script) => !script.src).length,
        mixedContent,
        consoleErrors: [],
        failedRequests: [],
      };
    }).then((result) => ({
      ...result,
      consoleErrors: Array.from(new Set(consoleErrors)).slice(0, 10),
      failedRequests: Array.from(new Set(failedRequests)).slice(0, 10),
    }));
  } catch (error) {
    return {
      finalUrl: url.toString(),
      title: null,
      forms: 0,
      passwordInputs: 0,
      externalScripts: 0,
      inlineScripts: 0,
      mixedContent: [],
      consoleErrors: [
        error instanceof Error ? error.message : "Browser inspection failed.",
      ],
      failedRequests: [],
    };
  } finally {
    await browser.close();
  }
}

async function inspectEcommerce(url: URL, homeHtml: string): Promise<EcommerceSignal> {
  const discovered = await discoverUrls(url, homeHtml);
  const pages = await Promise.all(
    discovered.slice(0, 14).map((pageUrl) => inspectPage(pageUrl)),
  );
  const allText = `${homeHtml}\n${pages.map((page) => page.scripts.join("\n")).join("\n")}\n${pages
    .map((page) => page.url)
    .join("\n")}`;
  const platform = detectNames(PLATFORM_HINTS, allText);
  const paymentProviders = Array.from(
    new Set(pages.flatMap((page) => page.providers).concat(detectNames(PROVIDERS, allText))),
  );
  const policies = {
    privacy: hasPageKind(pages, "policy", /privacy/i),
    terms: hasPageKind(pages, "policy", /terms|conditions|service/i),
    refund: hasPageKind(pages, "policy", /refund|return|cancel/i),
    contact: pages.some(
      (page) =>
        /contact/i.test(page.url) && page.status !== null && page.status < 400,
    ),
  };
  const lower = homeHtml.toLowerCase();
  const ecomSignals = [
    /add to cart|checkout|cart|sku|product|buy now|захиалах|сагс|төлөх|худалдан/i.test(
      homeHtml,
    ),
    pages.some(
      (page) =>
        ["cart", "checkout", "product"].includes(page.kind) &&
        page.status !== null &&
        page.status < 400,
    ),
    paymentProviders.length > 0,
    platform.length > 0,
  ];

  return {
    isLikelyEcommerce: ecomSignals.filter(Boolean).length >= 2,
    platform,
    paymentProviders,
    qpayDetected: paymentProviders.includes("QPay") || /\bqpay\b|qpay\.mn/i.test(lower),
    pagesChecked: pages,
    discoveredUrls: discovered.map((item) => item.toString()),
    policies,
    cookieConsent: /cookie|cookies|consent|privacy settings|tracking/i.test(homeHtml),
    checkoutPages: pages.filter(
      (page) => page.kind === "checkout" && page.status !== null && page.status < 400,
    ).length,
    cartPages: pages.filter(
      (page) => page.kind === "cart" && page.status !== null && page.status < 400,
    ).length,
    loginPages: pages.filter(
      (page) => page.kind === "login" && page.status !== null && page.status < 400,
    ).length,
    suspiciousCheckoutScripts: Array.from(
      new Set(
        pages
          .filter((page) => page.kind === "checkout")
          .flatMap((page) => {
            const pageHost = (() => {
              try { return new URL(page.url).hostname; } catch { return ""; }
            })();
            return page.scripts.filter((script) => isSuspiciousCheckoutScript(script, pageHost));
          }),
      ),
    ).slice(0, 12),
    riskyClientPaymentSignals: Array.from(
      new Set(pages.flatMap((page) => page.riskyClientPaymentSignals)),
    ).slice(0, 12),
    ...calculatePaymentBypassRisk(
      Array.from(new Set(pages.flatMap((page) => page.riskyClientPaymentSignals))),
      pages,
      paymentProviders,
    ),
    activePaymentBypassTested: false,
    activePaymentBypassNote:
      "The scanner does not attempt free purchases, payment bypass, brute force, or exploit payloads against live shops. It flags public client-side payment tampering signals and tells the owner where an authorized test is needed.",
  };
}

async function discoverUrls(base: URL, homeHtml: string) {
  const urls = new Map<string, URL>();
  const add = (candidate: string) => {
    try {
      const next = new URL(candidate, base);
      next.hash = "";
      if (next.hostname === base.hostname && ["http:", "https:"].includes(next.protocol)) {
        urls.set(next.toString(), next);
      }
    } catch {}
  };

  add(base.toString());
  KEY_PATHS.forEach(add);
  extractLinks(homeHtml).forEach(add);

  for (const sitemapUrl of ["/robots.txt", "/sitemap.xml"]) {
    const target = new URL(sitemapUrl, base);
    const text = await fetchText(target).catch(() => "");
    if (sitemapUrl === "/robots.txt") {
      text
        .split(/\r?\n/)
        .map((line) => line.match(/^sitemap:\s*(.+)$/i)?.[1])
        .filter((item): item is string => Boolean(item))
        .forEach(add);
    }
    extractLinks(text).forEach(add);
  }

  return Array.from(urls.values())
    .filter((item) => isUsefulEcommerceUrl(item) || item.toString() === base.toString())
    .slice(0, 22);
}

async function inspectPage(url: URL): Promise<PageSignal> {
  const response = await fetchHeadersAndHtml(url).catch(() => null);
  const html = response?.body ?? "";
  const scripts = extractScriptSources(html, url);
  const providers = detectNames(PROVIDERS, `${html}\n${scripts.join("\n")}`);
  const kind = classifyPage(url, html);
  const paymentInputs = countMatches(
    html,
    /name=["']?(card|cc|cvc|cvv|exp|expiry|amount|total|price|payment|invoice|qpay)|type=["']?(number|tel)/gi,
  );
  const riskyClientPaymentSignals = detectRiskyClientPaymentSignals(url, html);

  return {
    url: response?.finalUrl ?? url.toString(),
    status: response?.status ?? null,
    title: html.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.trim() ?? null,
    kind,
    https: (response?.finalUrl ? new URL(response.finalUrl) : url).protocol === "https:",
    forms: countMatches(html, /<form\b/gi),
    passwordInputs: countMatches(html, /type=["']?password/gi),
    paymentInputs,
    scripts,
    providers,
    riskyClientPaymentSignals,
  };
}

function buildFindings(
  response: Awaited<ReturnType<typeof fetchHeadersAndHtml>>,
  tlsSignal: TlsSignal,
  browser: BrowserSignal,
  dnsSignal: DnsSignal,
  ecommerce: EcommerceSignal,
) {
  const findings: Finding[] = [];
  const headers = response.headers;
  const finalUrl = new URL(response.finalUrl);

  if (finalUrl.protocol !== "https:") {
    findings.push(finding("no-https", "Page is not using HTTPS", "critical", "Transport", "The final page URL is HTTP.", "Visitors can have traffic read or changed in transit.", "Serve the site over HTTPS and redirect all HTTP traffic to HTTPS."));
  }

  if (tlsSignal.enabled && tlsSignal.authorized === false) {
    findings.push(finding("tls-invalid", "TLS certificate is not trusted", "critical", "Transport", "The TLS handshake completed, but Node did not authorize the certificate.", "Browsers may show a scary warning and attackers can impersonate the site.", "Install a valid certificate for this hostname and include the full certificate chain."));
  }

  if (tlsSignal.protocol && ["TLSv1", "TLSv1.1"].includes(tlsSignal.protocol)) {
    findings.push(finding("tls-old", "Old TLS protocol is enabled", "high", "Transport", `Negotiated protocol: ${tlsSignal.protocol}.`, "Old TLS versions have known weaknesses and may fail modern compliance checks.", "Disable TLS 1.0/1.1 and prefer TLS 1.2 or TLS 1.3."));
  }

  if (!headers["strict-transport-security"] && finalUrl.protocol === "https:") {
    findings.push(finding("missing-hsts", "Missing HSTS header", "medium", "Headers", "Strict-Transport-Security was not present.", "Returning visitors can still be downgraded to HTTP before the browser knows to force HTTPS.", "Add Strict-Transport-Security with a long max-age after confirming HTTPS works everywhere."));
  }

  if (!headers["content-security-policy"]) {
    findings.push(finding("missing-csp", "Missing Content Security Policy", "high", "Headers", "Content-Security-Policy was not present.", "A single script injection bug can become much easier to exploit.", "Add a restrictive CSP that allows only the scripts, styles, frames, and connections the app actually needs."));
  } else if (/\bunsafe-inline\b|\*/i.test(headers["content-security-policy"])) {
    findings.push(finding("weak-csp", "CSP allows risky sources", "medium", "Headers", headers["content-security-policy"], "Broad CSP sources reduce protection against cross-site scripting.", "Remove wildcards and unsafe-inline where possible; use nonces or hashes for required inline code."));
  }

  if (!headers["x-frame-options"] && !/frame-ancestors/i.test(headers["content-security-policy"] ?? "")) {
    findings.push(finding("clickjacking", "Missing clickjacking protection", "medium", "Headers", "No X-Frame-Options header or CSP frame-ancestors directive was found.", "Attackers can embed the page in another site and trick users into clicking hidden controls.", "Set CSP frame-ancestors or X-Frame-Options: DENY/SAMEORIGIN."));
  }

  if (headers["x-content-type-options"]?.toLowerCase() !== "nosniff") {
    findings.push(finding("no-nosniff", "Missing nosniff protection", "low", "Headers", "X-Content-Type-Options: nosniff was not present.", "Browsers may try to interpret files as a different content type.", "Set X-Content-Type-Options: nosniff."));
  }

  if (!headers["referrer-policy"]) {
    findings.push(finding("no-referrer-policy", "Missing referrer policy", "low", "Privacy", "Referrer-Policy was not present.", "Full URLs can leak to third-party sites through the Referer header.", "Set Referrer-Policy, commonly strict-origin-when-cross-origin."));
  }

  if (!headers["permissions-policy"]) {
    findings.push(finding("no-permissions-policy", "Missing browser permissions policy", "low", "Privacy", "Permissions-Policy was not present.", "Unused browser features remain available to embedded or compromised code.", "Set Permissions-Policy to disable camera, microphone, geolocation, and other unused features."));
  }

  const cookieHeader = headers["set-cookie"] ?? "";
  if (cookieHeader && !/;\s*secure/i.test(cookieHeader) && finalUrl.protocol === "https:") {
    findings.push(finding("cookie-secure", "Cookie missing Secure flag", "high", "Cookies", "At least one Set-Cookie header did not include Secure.", "Session cookies can be sent over HTTP if an HTTP endpoint exists.", "Add the Secure flag to authentication and state cookies."));
  }

  if (cookieHeader && !/;\s*httponly/i.test(cookieHeader)) {
    findings.push(finding("cookie-httponly", "Cookie missing HttpOnly flag", "medium", "Cookies", "At least one Set-Cookie header did not include HttpOnly.", "Injected JavaScript may be able to steal cookie values.", "Add HttpOnly to cookies that do not need browser JavaScript access."));
  }

  if (cookieHeader && !/;\s*samesite/i.test(cookieHeader)) {
    findings.push(finding("cookie-samesite", "Cookie missing SameSite flag", "low", "Cookies", "At least one Set-Cookie header did not include SameSite.", "Cookies without SameSite may be sent on cross-site requests, which increases CSRF risk.", "Add SameSite=Strict or SameSite=Lax to cookies that do not need cross-origin access."));
  }

  if (headers["x-powered-by"]) {
    findings.push(finding("x-powered-by", "Server technology disclosed via X-Powered-By", "low", "Headers", `X-Powered-By: ${headers["x-powered-by"]}`, "Knowing the specific framework version makes it easier to target known vulnerabilities.", "Remove or suppress the X-Powered-By header in your server or framework configuration."));
  }

  if (tlsSignal.validTo) {
    const expiresAt = new Date(tlsSignal.validTo);
    const daysLeft = Math.floor((expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    if (daysLeft < 30) {
      findings.push(finding(
        "cert-expiry-soon",
        `TLS certificate expires in ${daysLeft} day${daysLeft === 1 ? "" : "s"}`,
        daysLeft < 7 ? "critical" : "high",
        "Transport",
        `Certificate valid to: ${tlsSignal.validTo}`,
        "When the certificate expires visitors see a browser warning and HTTPS stops working.",
        "Renew the certificate before it expires; consider automated renewal with Let's Encrypt.",
      ));
    }
  }

  if (browser.passwordInputs > 0 && finalUrl.protocol !== "https:") {
    findings.push(finding("password-http", "Password field appears on an insecure page", "critical", "Forms", `${browser.passwordInputs} password input(s) were found on HTTP.`, "Credentials can be intercepted or modified in transit.", "Move login and account forms to HTTPS immediately."));
  }

  if (browser.mixedContent.length) {
    findings.push(finding("mixed-content", "HTTPS page loads HTTP assets", "high", "Browser", browser.mixedContent.join(", "), "Mixed content can be blocked by browsers or modified by attackers.", "Load all images, scripts, styles, and frames over HTTPS."));
  }

  if (browser.inlineScripts > 8 && !headers["content-security-policy"]) {
    findings.push(finding("inline-script-surface", "Large inline script surface without CSP", "medium", "Browser", `${browser.inlineScripts} inline script blocks were found.`, "Inline scripts make XSS containment harder when no CSP is present.", "Move inline scripts to bundled assets and use a CSP nonce/hash strategy."));
  }

  if (browser.consoleErrors.length || browser.failedRequests.length) {
    findings.push(finding("runtime-errors", "Browser runtime problems detected", "medium", "Reliability", [...browser.consoleErrors, ...browser.failedRequests].slice(0, 4).join(" | "), "Broken scripts and failed resources can disable security controls or important user flows.", "Fix failed browser requests and JavaScript errors found during page load."));
  }

  addEcommerceFindings(findings, ecommerce, dnsSignal);

  const presentHeaders = SECURITY_HEADERS.filter((header) => headers[header]);
  findings.push(finding("header-coverage", "Security header coverage", "good", "Headers", `${presentHeaders.length}/${SECURITY_HEADERS.length} expected headers were present.`, "More complete browser security headers reduce common client-side attack paths.", "Keep security headers intentional and test them after every deployment."));

  return findings;
}

function addEcommerceFindings(
  findings: Finding[],
  ecommerce: EcommerceSignal,
  dnsSignal: DnsSignal,
) {
  const sensitiveInsecurePages = ecommerce.pagesChecked.filter(
    (page) =>
      !page.https &&
      ["checkout", "cart", "login"].includes(page.kind) &&
      (page.forms || page.passwordInputs || page.paymentInputs),
  );
  if (sensitiveInsecurePages.length) {
    findings.push(finding("ecom-insecure-sensitive-page", "Checkout, cart, or login page is not HTTPS", "critical", "E-commerce", sensitiveInsecurePages.map((page) => page.url).join(", "), "Customer credentials, addresses, and payment intent can be intercepted or changed.", "Force HTTPS for every cart, checkout, login, account, and payment URL."));
  }

  if (ecommerce.isLikelyEcommerce && ecommerce.checkoutPages === 0) {
    findings.push(finding("checkout-not-found", "Checkout page was not discovered", "medium", "E-commerce", `${ecommerce.pagesChecked.length} public pages were checked.`, "The scanner cannot confirm checkout safety if the checkout path is hidden, blocked, or only created after cart actions.", "Expose predictable checkout/cart paths or run an authenticated/manual checkout test for this site."));
  }

  if (ecommerce.isLikelyEcommerce && !ecommerce.paymentProviders.length) {
    findings.push(finding("payment-provider-not-found", "Payment provider was not detected", "medium", "Payments", "No Stripe, PayPal, Shopify, WooCommerce, QPay, MonPay, SocialPay, or similar payment signal was found.", "Customers may not know who handles payment, and custom payment flows need deeper manual review.", "Document the payment provider and keep sensitive card/payment handling on trusted PCI-compliant provider pages."));
  }

  if (ecommerce.qpayDetected) {
    findings.push(finding("qpay-detected", "QPay payment signal detected", "info", "Payments", "QPay strings, links, or scripts were found in public pages.", "QPay itself is normal for Mongolian e-commerce, but order status must be verified server-side after bank/payment confirmation.", "Confirm the backend verifies QPay invoice status server-side and never marks orders paid from browser-only callbacks or editable client values."));
  }

  if (ecommerce.riskyClientPaymentSignals.length) {
    findings.push(finding("client-payment-tamper-risk", "Client-side payment tampering signals found", ecommerce.paymentBypassRiskLevel === "critical" ? "critical" : "high", "Payments", `Risk ${ecommerce.paymentBypassRiskScore}/100 (${ecommerce.paymentBypassRiskLevel}). ${ecommerce.riskyClientPaymentSignals.join(" | ")}`, "If the server trusts browser-submitted amount, total, invoice, or paid status values, a buyer may change price or order state.", "Recalculate totals on the server, verify QPay/provider invoice status server-side, and ignore client-submitted paid/amount/order status fields."));
  } else if (ecommerce.isLikelyEcommerce) {
    findings.push(finding("payment-bypass-surface", "No obvious public payment-bypass signal found", "good", "Payments", `Risk ${ecommerce.paymentBypassRiskScore}/100 (${ecommerce.paymentBypassRiskLevel}). The public scan did not find editable paid/amount/order status signals.`, "This lowers obvious risk, but it does not prove checkout is safe because server logic and authenticated order flows are not visible publicly.", "Run an authorized staging checkout test: change client totals/status in DevTools, complete QPay sandbox flow, and verify the backend recalculates totals and confirms provider invoice status server-side."));
  }

  if (ecommerce.suspiciousCheckoutScripts.length) {
    findings.push(finding("checkout-third-party-scripts", "Unusual third-party scripts on checkout", "high", "Payments", ecommerce.suspiciousCheckoutScripts.join(", "), "Third-party code on checkout can observe customer details or interfere with payment flows.", "Allow only required analytics/payment scripts on checkout and enforce a strict checkout CSP."));
  }

  if (ecommerce.isLikelyEcommerce && !ecommerce.policies.privacy) {
    findings.push(finding("privacy-policy-missing", "Privacy policy was not found", "medium", "Trust", "No public privacy policy path/link was discovered.", "Customers may not know how personal data, addresses, phone numbers, and payment metadata are handled.", "Add a clear privacy policy linked from footer, checkout, and account pages."));
  }

  if (ecommerce.isLikelyEcommerce && !ecommerce.policies.refund) {
    findings.push(finding("refund-policy-missing", "Refund or return policy was not found", "medium", "Trust", "No refund/return/cancellation policy path/link was discovered.", "Payment disputes and customer support load increase when refund terms are unclear.", "Add refund, return, cancellation, and delivery terms near checkout and in the footer."));
  }

  if (ecommerce.isLikelyEcommerce && !ecommerce.cookieConsent) {
    findings.push(finding("cookie-consent-not-detected", "Cookie consent or tracking notice was not detected", "low", "Privacy", "No visible cookie/consent/tracking signal was found in public HTML.", "If analytics, ads, chat, or retargeting scripts run, visitors may not be informed.", "Add consent handling appropriate to the markets where the shop sells."));
  }

  if (!dnsSignal.mx.length && ecommerce.isLikelyEcommerce) {
    findings.push(finding("mx-missing", "No MX records found", "medium", "DNS", "The root domain has no MX record.", "Order emails, support replies, password resets, and dispute handling may fail or look suspicious.", "Configure reliable mail hosting and test order/support email delivery."));
  }

  if (!dnsSignal.spf && ecommerce.isLikelyEcommerce) {
    findings.push(finding("spf-missing", "SPF record was not found", "medium", "DNS", "No v=spf1 TXT record was found.", "Attackers can spoof shop emails more easily, hurting order trust and deliverability.", "Add SPF for all services that send mail for this domain."));
  }

  if (!dnsSignal.dmarc && ecommerce.isLikelyEcommerce) {
    findings.push(finding("dmarc-missing", "DMARC record was not found", "medium", "DNS", "No _dmarc TXT record was found.", "Fake order, invoice, and refund emails are harder for receivers to reject.", "Add DMARC, start with monitoring, then move toward quarantine or reject."));
  }

  if (dnsSignal.dmarc && /p=none/i.test(dnsSignal.dmarc)) {
    findings.push(finding("dmarc-not-enforced", "DMARC is in monitoring mode only (p=none)", "medium", "DNS", dnsSignal.dmarc, "Spoofed emails from your domain are not rejected by receiving mail servers — only reported.", "Move to p=quarantine then p=reject after reviewing DMARC aggregate reports for 2–4 weeks."));
  }

  if (dnsSignal.spf && /\+all/i.test(dnsSignal.spf)) {
    findings.push(finding("spf-allow-all", "SPF record allows any server to send email (+all)", "high", "DNS", dnsSignal.spf, "Any server on the internet can send email that appears to come from this domain.", "Replace +all with -all and list only the sending services you actually use."));
  } else if (dnsSignal.spf && /~all/i.test(dnsSignal.spf)) {
    findings.push(finding("spf-softfail", "SPF uses soft-fail (~all) — not a hard reject", "low", "DNS", dnsSignal.spf, "Receiving servers may still accept spoofed email that fails SPF instead of rejecting it.", "Upgrade to -all (hard fail) once all legitimate sending sources are listed in the record."));
  }

  if (!dnsSignal.caa.length) {
    findings.push(finding("caa-missing", "CAA record was not found", "low", "DNS", "No CAA record was found.", "Any certificate authority may be able to issue certificates for the domain.", "Add CAA records for the certificate authorities you actually use."));
  }
}

function buildMetrics(
  findings: Finding[],
  response: Awaited<ReturnType<typeof fetchHeadersAndHtml>>,
  tlsSignal: TlsSignal,
  browser: BrowserSignal,
  dnsSignal: DnsSignal,
  ecommerce: EcommerceSignal,
): Metric[] {
  const headersPresent = SECURITY_HEADERS.filter(
    (header) => response.headers[header],
  ).length;
  const issuePenalty = (category: string) =>
    findings
      .filter((finding) => finding.category === category)
      .reduce((total, finding) => total + severityPenalty(finding.severity), 0);
  const policyCount = Object.values(ecommerce.policies).filter(Boolean).length;
  const dnsScore =
    (dnsSignal.mx.length ? 25 : 0) +
    (dnsSignal.spf ? 25 : 0) +
    (dnsSignal.dmarc ? 30 : 0) +
    (dnsSignal.caa.length ? 20 : 0);

  return [
    {
      label: "Transport",
      score: clampScore(
        (new URL(response.finalUrl).protocol === "https:" ? 100 : 15) -
          issuePenalty("Transport"),
      ),
      weight: 1.2,
      summary: tlsSignal.protocol
        ? `${tlsSignal.protocol}, ${tlsSignal.authorized ? "trusted cert" : "certificate warning"}`
        : "No HTTPS transport confirmed",
    },
    {
      label: "Headers",
      score: clampScore(
        (headersPresent / SECURITY_HEADERS.length) * 100 - issuePenalty("Headers"),
      ),
      weight: 1.1,
      summary: `${headersPresent}/${SECURITY_HEADERS.length} important headers present`,
    },
    {
      label: "E-commerce",
      score: clampScore(
        (ecommerce.isLikelyEcommerce ? 70 : 45) +
          (ecommerce.checkoutPages ? 10 : 0) +
          (ecommerce.paymentProviders.length ? 10 : 0) +
          (policyCount / 4) * 10 -
          issuePenalty("E-commerce") -
          issuePenalty("Trust"),
      ),
      weight: 1.4,
      summary: `${ecommerce.pagesChecked.length} pages checked, ${ecommerce.paymentProviders.length} payment provider signals`,
    },
    {
      label: "Payments",
      score: clampScore(
        90 -
          issuePenalty("Payments") -
          ecommerce.paymentBypassRiskScore * 0.45 -
          ecommerce.suspiciousCheckoutScripts.length * 8 -
          ecommerce.riskyClientPaymentSignals.length * 6,
      ),
      weight: 1.3,
      summary: `${ecommerce.paymentBypassRiskLevel} bypass risk (${ecommerce.paymentBypassRiskScore}/100), ${ecommerce.qpayDetected ? "QPay detected" : ecommerce.paymentProviders.join(", ") || "no provider detected"}`,
    },
    {
      label: "DNS / Email",
      score: clampScore(dnsScore - issuePenalty("DNS")),
      weight: 0.9,
      summary: `${dnsSignal.mx.length ? "MX" : "no MX"}, ${dnsSignal.spf ? "SPF" : "no SPF"}, ${dnsSignal.dmarc ? "DMARC" : "no DMARC"}`,
    },
    {
      label: "Browser Runtime",
      score: clampScore(100 - issuePenalty("Browser") - issuePenalty("Reliability")),
      weight: 0.8,
      summary: `${browser.consoleErrors.length} console errors, ${browser.failedRequests.length} failed requests`,
    },
  ];
}

async function createAiReview(
  scan: unknown,
  language: ReportLanguage,
): Promise<{
  review: string | null;
  model: string | null;
  error: string | null;
}> {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) {
    return {
      review: null,
      model: null,
      error: "Set GEMINI_API_KEY to enable the AI deep review.",
    };
  }

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${apiKey}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          systemInstruction: {
            parts: [
              {
                text:
                  language === "mn"
                    ? "Та хамгаалалтын зорилготой e-commerce вэб шалгагч. Зөвхөн өгөгдсөн нотолгоог ашигла. Бодит exploit, төлбөр тойрох оролдлого, brute force хийсэн мэт бүү хэл. Монгол хэлээр тодорхой, энгийн, үйлдэлтэй зөвлөгөө өг."
                    : "You are a defensive e-commerce web security reviewer. Use only the provided scan evidence. Do not claim active exploitation, payment bypass, credential access, or brute force. Give practical risks and fixes.",
              },
            ],
          },
          contents: [
            {
              role: "user",
              parts: [
                {
                  text:
                    language === "mn"
                      ? `Энэ e-commerce вэбийн аюулгүй байдлын тайланг Монгол хэлээр гарга. Худалдагч ойлгохоор: ерөнхий дүгнэлт, хамгийн аюултай 5 зүйл, QPay/төлбөр дээр юу шалгах, хэрэглэгчид юу тохиолдож болох, засах дараалал. Нотолгоо JSON:\n${JSON.stringify(scan).slice(0, 22000)}`
                      : `Create a concise e-commerce safety review. Include overall verdict, top 5 risks, payment/QPay checks needed, what can happen to customers/owner, and fix order. Evidence JSON:\n${JSON.stringify(scan).slice(0, 22000)}`,
                },
              ],
            },
          ],
          generationConfig: {
            temperature: 0.2,
            maxOutputTokens: 2500,
          },
        }),
      },
    );

    if (!response.ok) {
      return {
        review: null,
        model: GEMINI_MODEL,
        error: `Gemini request failed with ${response.status}.`,
      };
    }

    const json = (await response.json()) as {
      candidates?: { content?: { parts?: { text?: string }[] } }[];
    };
    const text = json.candidates?.[0]?.content?.parts
      ?.map((part) => part.text ?? "")
      .join("")
      .trim();

    return {
      review: text || null,
      model: GEMINI_MODEL,
      error: text ? null : "Gemini returned an empty review.",
    };
  } catch (error) {
    return {
      review: null,
      model: GEMINI_MODEL,
      error: error instanceof Error ? error.message : "Gemini review failed.",
    };
  }
}

function finding(
  id: string,
  title: string,
  severity: Severity,
  category: string,
  evidence: string,
  impact: string,
  recommendation: string,
): Finding {
  return { id, title, severity, category, evidence, impact, recommendation };
}

function scoreToGrade(score: number) {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

function severityPenalty(severity: Severity) {
  switch (severity) {
    case "critical":
      return 55;
    case "high":
      return 35;
    case "medium":
      return 18;
    case "low":
      return 8;
    default:
      return 0;
  }
}

function clampScore(score: number) {
  return Math.max(0, Math.min(100, Math.round(score)));
}

function emptyTls(enabled: boolean): TlsSignal {
  return {
    enabled,
    authorized: null,
    protocol: null,
    cipher: null,
    validFrom: null,
    validTo: null,
    issuer: null,
    subject: null,
  };
}

function isPrivateAddress(address: string) {
  if (net.isIPv4(address)) {
    const [a, b] = address.split(".").map(Number);
    return (
      a === 10 ||
      a === 127 ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 169 && b === 254) ||
      a === 0
    );
  }

  const normalized = address.toLowerCase();
  return (
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}

async function fetchText(url: URL) {
  const response = await fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(12000),
    headers: { "User-Agent": "Mozilla/5.0 SecurityReviewBot/1.0" },
  });
  if (!response.ok) return "";
  return await response.text();
}

function extractLinks(text: string) {
  const links = new Set<string>();
  const patterns = [
    /\bhref=["']([^"']+)["']/gi,
    /\bloc>\s*([^<]+)\s*<\/loc>/gi,
    /\bhttps?:\/\/[^\s"'<>]+/gi,
  ];
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      links.add(match[1] ?? match[0]);
    }
  }
  return Array.from(links);
}

function extractScriptSources(html: string, base: URL) {
  return Array.from(html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi))
    .map((match) => {
      try {
        return new URL(match[1], base).toString();
      } catch {
        return match[1];
      }
    })
    .slice(0, 60);
}

function isUsefulEcommerceUrl(url: URL) {
  return /(cart|checkout|login|account|product|shop|store|privacy|terms|refund|return|contact|pay|payment|order|qpay|сагс|төлбөр|захиалга)/i.test(
    url.pathname,
  );
}

function classifyPage(url: URL, html: string): PageSignal["kind"] {
  const path = url.pathname.toLowerCase();

  // URL path is the primary signal — site-wide nav/footer keywords pollute HTML content
  if (/\/(checkout|payment|pay|order\/confirm|qpay)/.test(path)) return "checkout";
  if (/\/(cart|basket|bag)/.test(path)) return "cart";
  if (/\/(login|sign-in|signin|нэвтрэх)/.test(path)) return "login";
  if (/\/(account|profile|my-account|dashboard)/.test(path)) return "login";
  if (/\/(privacy|terms|refund|return|policy|нөхцөл|буцаалт|contact)/.test(path)) return "policy";
  if (/\/(product|products|shop|store|catalog|захиалах|худалдан)/.test(path)) return "product";
  if (path === "/" || path === "") return "home";

  // Fall back to HTML only when URL is ambiguous — use specific structural patterns
  const snippet = html.slice(0, 3000);
  if (/<form[^>]*action[^>]*checkout|id=["']checkout/i.test(snippet)) return "checkout";
  if (/<input[^>]+type=["']password/i.test(snippet)) return "login";
  if (/add to cart|buy now|захиалах/i.test(snippet)) return "product";

  return "other";
}

function detectNames(patterns: Record<string, RegExp>, text: string) {
  return Object.entries(patterns)
    .filter(([, pattern]) => pattern.test(text))
    .map(([name]) => name);
}

function countMatches(text: string, pattern: RegExp) {
  return Array.from(text.matchAll(pattern)).length;
}

function detectRiskyClientPaymentSignals(url: URL, html: string) {
  const signals: string[] = [];
  const snippets = html.slice(0, 180000);
  const checks: [RegExp, string][] = [
    [/<input[^>]+type=["']?hidden[^>]+name=["']?(amount|total|price|paid|payment_status|order_status|invoice|invoice_id|qpay_invoice)["']?/i, "Hidden payment amount/status/invoice field appears in HTML"],
    [/name=["']?(amount|total|price|paid|payment_status|order_status|invoice|invoice_id|qpay_invoice)["']?/i, "Payment amount/status/invoice appears in client-editable form fields"],
    [/\b(localStorage|sessionStorage)\b.{0,120}\b(cart|checkout|payment|order|total|amount|paid|invoice|qpay)\b/i, "Cart/payment state appears stored in browser storage"],
    [/\b(amount|total|price|paid|status|invoice)\b.{0,80}(URLSearchParams|location\.search|query|getParameter|router\.query)/i, "Payment amount/status/invoice appears connected to URL query parameters"],
    [/\bpaid\s*[:=]\s*(true|1)|payment_status\s*[:=]\s*["']?paid|order_status\s*[:=]\s*["']?(paid|complete|completed)/i, "Paid/order status literal appears in client code"],
    [/\b(qpay|invoice)\b.{0,160}\b(callback|success|paid|status|deeplink|qr|check|verify)\b/i, "QPay/invoice status handling appears in public client code"],
    [/\b(fetch|axios|XMLHttpRequest)\b.{0,160}\b(mark.?paid|payment.?success|order.?complete|update.?order|confirm.?payment)\b/i, "Browser code appears able to call payment/order status endpoints"],
    [/\b(total|amount|price)\b.{0,80}\b(parseFloat|parseInt|Number\(|\+document|input\.value)/i, "Checkout total appears calculated from client-controlled values"],
    [/\b(discount|coupon|promo)\b.{0,100}\b(total|amount|price)\b/i, "Discount or coupon logic appears near client-side totals"],
  ];

  for (const [pattern, label] of checks) {
    if (pattern.test(snippets)) {
      signals.push(`${label} on ${url.pathname || "/"}`);
    }
  }

  return signals;
}

function calculatePaymentBypassRisk(
  signals: string[],
  pages: PageSignal[],
  paymentProviders: string[],
) {
  const checkoutPages = pages.filter((page) => page.kind === "checkout");
  const checkoutSignals = checkoutPages.reduce(
    (total, page) => total + page.riskyClientPaymentSignals.length,
    0,
  );
  const paymentInputs = pages.reduce((total, page) => total + page.paymentInputs, 0);
  const score = clampScore(
    signals.length * 16 +
      checkoutSignals * 10 +
      Math.min(paymentInputs * 4, 18) +
      (checkoutPages.length && !paymentProviders.length ? 18 : 0),
  );

  return {
    paymentBypassRiskScore: score,
    paymentBypassRiskLevel:
      score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low",
  } as const;
}

function isSuspiciousCheckoutScript(scriptUrl: string, siteHost = "") {
  if (
    /stripe|paypal|qpay|shopify|woocommerce|monpay|socialpay|google|googletagmanager|facebook|meta|cloudflare|cdn\.jsdelivr|unpkg/i.test(
      scriptUrl,
    )
  ) {
    return false;
  }

  try {
    const host = new URL(scriptUrl).hostname;
    if (siteHost && host === siteHost) return false; // first-party scripts are never suspicious
    return Boolean(host) && !/^\w+\.(js|css)$/i.test(host);
  } catch {
    return false;
  }
}

function hasPageKind(
  pages: PageSignal[],
  kind: PageSignal["kind"],
  urlPattern: RegExp,
) {
  return pages.some(
    (page) =>
      page.kind === kind &&
      urlPattern.test(page.url) &&
      page.status !== null &&
      page.status < 400,
  );
}
