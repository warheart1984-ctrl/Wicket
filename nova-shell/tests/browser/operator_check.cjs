// Drives the operator screen in a real browser. Prints one JSON object of results.
// usage: node operator_check.cjs <base-url> <token> <screenshot-dir> <hostile-text>
const { chromium } = require("playwright");

const [base, token, shots, hostile] = process.argv.slice(2);
const results = { errors: [], dialogs: [], unauthorized: 0 };

(async () => {
const browser = await chromium.launch();
try {
  const context = await browser.newContext({ viewport: { width: 1100, height: 900 } });
  const page = await context.newPage();
  page.on("pageerror", (e) => results.errors.push("pageerror: " + e.message));
  page.on("console", (m) => {
    if (m.type() !== "error") return;
    // The deliberate wrong-token probe below produces exactly one 401; count it, flag anything else.
    if (/status of 401/.test(m.text())) results.unauthorized += 1;
    else results.errors.push("console: " + m.text());
  });
  page.on("dialog", async (d) => { results.dialogs.push(d.message()); await d.accept(); });

  // 1. no token -> the sign-in form, and no data
  await page.goto(base + "/");
  await page.waitForSelector("#login:not([hidden])");
  results.login_shown = true;
  results.app_hidden_without_token = await page.locator("#app").isHidden();

  // 2. a wrong token is rejected and sends you back to sign-in
  await page.fill("#token-input", "not-the-token");
  await page.click("#login-form button");
  await page.waitForSelector("#banner.show");
  results.wrong_token_message = await page.locator("#banner").textContent();
  await page.waitForSelector("#login:not([hidden])");

  // 3. the real link signs in; hostile text must appear as plain text
  await page.goto(`${base}/#token=${encodeURIComponent(token)}`);
  await page.waitForSelector("#pending-body tr");
  results.pending_rows = await page.locator("#pending-body tr").count();
  results.target_text = await page.locator("#pending-body tr td:nth-child(2)").first().textContent();
  results.hostile_rendered_literally = results.target_text.includes(hostile);
  results.injected_elements = await page.locator("#pending-body img, #pending-body script").count();
  results.xss_ran = await page.evaluate(() => window.__xss === 1);
  results.injected_in_chips = await page.locator("#chips img, #chips script").count();
  results.hash_after_signin = await page.evaluate(() => location.hash);
  results.chips = await page.locator("#chips .chip").allTextContents();

  // 4. layout: dark mode and a phone-sized screen
  await page.screenshot({ path: `${shots}/operator-light.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: "dark" });
  await page.screenshot({ path: `${shots}/operator-dark.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: "light" });
  await page.setViewportSize({ width: 390, height: 800 });
  results.phone_horizontal_overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth + 1);
  await page.screenshot({ path: `${shots}/operator-phone.png`, fullPage: true });
  await page.setViewportSize({ width: 1100, height: 900 });

  // 5. approve it
  await page.locator("#pending-body button").first().click();
  await page.waitForSelector("#approved-table:not([hidden])");
  results.pending_hidden_after = await page.locator("#pending-table").isHidden();
  results.approved_rows = await page.locator("#approved-body tr").count();
  results.approved_by = await page.locator("#approved-body tr td:nth-child(1)").first().textContent();
  results.published_button_hidden = await page.locator("#published-row").isHidden();  // no repo configured
  await page.screenshot({ path: `${shots}/operator-approved.png`, fullPage: true });
  await page.setViewportSize({ width: 390, height: 800 });  // hidden things must stay hidden on a phone too
  results.phone_pending_table_hidden = await page.locator("#pending-table").isHidden();
  results.phone_published_button_hidden = await page.locator("#published-row").isHidden();
} finally {
  await browser.close();
}
console.log(JSON.stringify(results));
})().catch((error) => { console.error(error); process.exit(1); });
