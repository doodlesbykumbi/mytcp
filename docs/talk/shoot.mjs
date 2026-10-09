// Screenshot every Reveal slide in one Chromium session.
//
//   npm run shoot                      # all slides → shots/
//   npm run shoot -- 13 15 28          # specific slides
//   URL=http://127.0.0.1:8766/ npm run shoot
import { chromium } from "playwright";
import { mkdir } from "node:fs/promises";

const url = process.env.URL ?? "http://127.0.0.1:8766/";
const outDir = new URL("./shots/", import.meta.url).pathname;
const only = process.argv.slice(2).map(Number);

await mkdir(outDir, { recursive: true });
const browser = await chromium.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 720 } });

await page.goto(`${url}?fragments=false&transition=none&autoAnimate=false`);
await page.waitForFunction(() => window.Reveal?.isReady());
await page.evaluate(() => document.fonts.ready);

const total = await page.evaluate(() => Reveal.getTotalSlides());
const indices = only.length ? only : [...Array(total).keys()];

for (const i of indices) {
  await page.evaluate((n) => Reveal.slide(n), i);
  await page.waitForTimeout(150);
  const file = `${outDir}s${String(i).padStart(2, "0")}.png`;
  await page.screenshot({ path: file });
  console.log(file);
}

await browser.close();
