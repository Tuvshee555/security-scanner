"use client";

import { FormEvent, useState } from "react";

interface ScrapedData {
  name: string | null;
  rating: number | null;
  address: string | null;
  category: string | null;
  reviews: string[];
  reviewTexts: string[];
}

const exampleUrl =
  "https://www.tripadvisor.co.nz/Restaurant_Review-g293956-d16759231-Reviews-Hansang_Restaurant-Ulaanbaatar.html";

export default function Home() {
  const [url, setUrl] = useState(exampleUrl);
  const [data, setData] = useState<ScrapedData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setIsLoading(true);
    setError(null);
    setData(null);

    try {
      const response = await fetch("/api/scrape", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });

      const result = (await response.json()) as {
        data?: ScrapedData;
        error?: string;
      };

      if (!response.ok) {
        throw new Error(result.error || "Scrape failed.");
      }

      setData(result.data ?? null);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Scrape failed.");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <main className="min-h-screen bg-background px-5 py-8 text-foreground sm:px-8">
      <div className="mx-auto flex w-full max-w-4xl flex-col gap-8">
        <header className="flex flex-col gap-3 border-b border-foreground/10 pb-6">
          <p className="font-mono text-sm uppercase tracking-wide text-foreground/60">
            TripAdvisor Scraper
          </p>
          <h1 className="max-w-2xl text-4xl font-semibold leading-tight sm:text-5xl">
            Extract restaurant details from a TripAdvisor page.
          </h1>
        </header>

        <form
          onSubmit={handleSubmit}
          className="grid gap-3 rounded-lg border border-foreground/10 bg-foreground/[0.03] p-4 sm:grid-cols-[1fr_auto]"
        >
          <label className="sr-only" htmlFor="url">
            TripAdvisor URL
          </label>
          <input
            id="url"
            value={url}
            onChange={(event) => setUrl(event.target.value)}
            className="min-h-11 rounded-md border border-foreground/15 bg-background px-3 text-sm outline-none transition focus:border-foreground/50"
            placeholder="https://www.tripadvisor.com/..."
            type="url"
            required
          />
          <button
            type="submit"
            disabled={isLoading}
            className="min-h-11 rounded-md bg-foreground px-5 text-sm font-medium text-background transition hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
          >
            {isLoading ? "Scraping..." : "Scrape"}
          </button>
        </form>

        {error ? (
          <section className="rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-700 dark:text-red-200">
            {error}
          </section>
        ) : null}

        {data ? (
          <section className="grid gap-4 rounded-lg border border-foreground/10 p-5">
            <div>
              <p className="font-mono text-xs uppercase text-foreground/50">
                Restaurant
              </p>
              <h2 className="mt-1 text-2xl font-semibold">
                {data.name || "Unknown"}
              </h2>
            </div>

            <dl className="grid gap-4 sm:grid-cols-3">
              <div>
                <dt className="text-sm text-foreground/60">Rating</dt>
                <dd className="font-medium">{data.rating ?? "Not found"}</dd>
              </div>
              <div>
                <dt className="text-sm text-foreground/60">Category</dt>
                <dd className="font-medium">{data.category || "Not found"}</dd>
              </div>
              <div>
                <dt className="text-sm text-foreground/60">Address</dt>
                <dd className="font-medium">{data.address || "Not found"}</dd>
              </div>
            </dl>

            <div className="grid gap-3">
              <h3 className="text-lg font-semibold">Reviews</h3>
              {[...data.reviews, ...data.reviewTexts].length ? (
                <ul className="grid gap-3">
                  {[...data.reviews, ...data.reviewTexts].map((review, index) => (
                    <li
                      className="rounded-md border border-foreground/10 p-3 text-sm text-foreground/80"
                      key={`${review}-${index}`}
                    >
                      {review}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-foreground/60">No reviews found.</p>
              )}
            </div>
          </section>
        ) : null}
      </div>
    </main>
  );
}
