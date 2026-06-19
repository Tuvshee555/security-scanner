import puppeteer from "puppeteer";

export interface ScrapedData {
  name: string | null;
  rating: number | null;
  address: string | null;
  category: string | null;
  reviews: string[];
  reviewTexts: string[];
}

export async function scrapeTripadvisor(url: string): Promise<ScrapedData> {
  const browser = await puppeteer.launch({
    headless: true,
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });

  try {
    const page = await browser.newPage();

    await page.setUserAgent(
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    );

    await page.setViewport({ width: 1200, height: 900 });
    await page.goto(url, { waitUntil: "networkidle2", timeout: 45000 });

    await page.waitForSelector('h1, [data-test-target="top-info-header"]', {
      timeout: 15000,
    });

    return await page.evaluate(() => {
      const getText = (sel: string) => {
        const el = document.querySelector(sel);
        return el instanceof HTMLElement ? el.innerText.trim() : null;
      };

      const name =
        getText("h1") || getText('[data-test-target="top-info-header"]');

      let rating: number | null = null;
      const ratingEl =
        document.querySelector('[aria-label*="of 5"]') ||
        document.querySelector('[data-test-target*="review-rating"]');
      if (ratingEl) {
        const label = ratingEl.getAttribute("aria-label") || ratingEl.textContent;
        const match = (label || "").match(/([\d.]+)\s+of\s+5/);
        if (match) rating = parseFloat(match[1]);
      }

      const address =
        getText('[data-test-target="restaurant-details"] address') ||
        getText(".ui_icon.map-pin + span") ||
        getText('[data-test-target="address"]');

      const category =
        getText('[data-test-target="restaurant-detail-about-cuisines"]') ||
        getText(".detail .cuisines");

      const reviews = Array.from(
        document.querySelectorAll(
          '[data-test-target="review-title"], .review-title',
        ),
      )
        .slice(0, 3)
        .map((review) =>
          review instanceof HTMLElement ? review.innerText.trim() : "",
        )
        .filter(Boolean);

      const reviewTexts = Array.from(
        document.querySelectorAll(
          '[data-test-target="review-comment"], .review-container .entry',
        ),
      )
        .slice(0, 3)
        .map((review) =>
          review instanceof HTMLElement ? review.innerText.trim() : "",
        )
        .filter(Boolean);

      return { name, rating, address, category, reviews, reviewTexts };
    });
  } finally {
    await browser.close();
  }
}
