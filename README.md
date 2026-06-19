# E-commerce Security Lab

A Mongolian-first defensive scanner for online shops. Enter a public URL and the app checks the public storefront, likely checkout/cart/login pages, payment signals, QPay hints, DNS/email trust, browser runtime problems, and common web security headers.

## What it checks

- HTTPS and TLS certificate trust
- security headers: CSP, HSTS, frame protection, nosniff, referrer policy, permissions policy
- cookie flags and browser runtime errors
- checkout, cart, login, product, policy, refund, contact, and payment-looking pages
- payment provider fingerprints: QPay, Stripe, PayPal, Shopify, WooCommerce, MonPay, SocialPay, and more
- QPay-specific public signals, with a reminder to verify invoice status server-side
- suspicious third-party scripts on checkout pages
- client-side payment tampering signals such as editable amount, paid status, order status, or invoice status fields
- a payment bypass risk score based on hidden payment fields, URL-controlled totals/status, browser storage, client-side total calculation, QPay callback/status handling, and browser-callable payment/order status endpoints
- privacy, terms, refund, contact, and cookie consent signals
- DNS records: MX, SPF, DMARC, and CAA
- optional Gemini-powered owner-friendly review in Mongolian or English

## Safety boundary

The scanner does not attempt free purchases, payment bypass, brute force, login attacks, exploit payloads, or destructive tests against live shops. Those tests require explicit authorization from the site owner and should be done in a staging or controlled production test flow.

## Gemini setup

The scanner works without an AI key, but the AI review panel needs:

```bash
GEMINI_API_KEY=your_key_here
```

The app uses `gemini-2.5-flash` for a good cost/quality balance.

## Development

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).
