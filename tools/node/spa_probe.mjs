import { chromium } from "playwright";

const target = process.argv[2] || "";
if (!target) {
  console.log(JSON.stringify({ error: "missing target" }));
  process.exit(0);
}

const url = `https://${target}`;
const out = {
  module: "node_spa_probe",
  target,
  url,
  hidden_requests: [],
  cookies: [],
  graphql_hint: false
};

try {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  page.on("request", (req) => {
    const u = req.url();
    if (out.hidden_requests.length < 40) out.hidden_requests.push(u);
    if (u.includes("/graphql")) out.graphql_hint = true;
  });
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30000 });
  await page.waitForTimeout(2500);
  out.cookies = await page.context().cookies();
  await browser.close();
} catch (err) {
  out.error = String(err);
}

console.log(JSON.stringify(out));
