// tripadvisor-scrape.js
// npm i puppeteer
const puppeteer = require("puppeteer");

async function scrape(url) {
  const browser = await puppeteer.launch({
    headless: true, // set false if you want to watch it
    args: ["--no-sandbox", "--disable-setuid-sandbox"],
  });
  const page = await browser.newPage();

  // Set a normal user-agent to reduce bot detection
  await page.setUserAgent(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
  );

  // Optional: set viewport
  await page.setViewport({ width: 1200, height: 900 });

  try {
    await page.goto(url, { waitUntil: "networkidle2", timeout: 45000 });

    // Wait for a top-level selector that indicates the restaurant was rendered
    await page.waitForSelector('h1, [data-test-target="top-info-header"]', {
      timeout: 15000,
    });

    const data = await page.evaluate(() => {
      const getText = (sel) => {
        const el = document.querySelector(sel);
        return el ? el.innerText.trim() : null;
      };

      // Name (often h1)
      const name =
        getText("h1") || getText('[data-test-target="top-info-header"]');

      // Rating — TripAdvisor sometimes uses aria-label like "4.0 of 5 bubbles"
      let rating = null;
      const ratingEl =
        document.querySelector('[aria-label*="of 5"]') ||
        document.querySelector('[data-test-target*="review-rating"]');
      if (ratingEl) {
        const al = ratingEl.getAttribute("aria-label") || ratingEl.textContent;
        const m = (al || "").match(/([\d.]+)\s+of\s+5/);
        if (m) rating = parseFloat(m[1]);
      }

      // Address
      const address =
        getText('[data-test-target="restaurant-details"] address') ||
        getText(".ui_icon.map-pin + span") ||
        getText('[data-test-target="address"]');

      // Category / cuisine
      const category =
        getText('[data-test-target="restaurant-detail-about-cuisines"]') ||
        getText(".detail .cuisines");

      // Top review snippets (collect first 3)
      const reviews = Array.from(
        document.querySelectorAll(
          '[data-test-target="review-title"], .review-title'
        )
      )
        .slice(0, 3)
        .map((r) => r.innerText.trim());

      // Example: gather first few review texts
      const reviewTexts = Array.from(
        document.querySelectorAll(
          '[data-test-target="review-comment"] , .review-container .entry'
        )
      )
        .slice(0, 3)
        .map((r) => r.innerText.trim());

      return { name, rating, address, category, reviews, reviewTexts };
    });

    console.log("Scraped data:", JSON.stringify(data, null, 2));
    await browser.close();
    return data;
  } catch (err) {
    await browser.close();
    throw err;
  }
}

const url =
  "https://www.tripadvisor.co.nz/Restaurant_Review-g293956-d16759231-Reviews-Hansang_Restaurant-Ulaanbaatar.html";
scrape(url).catch((err) => {
  console.error("Error scraping:", err.message || err);
});
