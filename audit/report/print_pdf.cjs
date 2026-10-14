// Print the audit report HTML to PDF with headless Chromium.
//   node audit/report/print_pdf.cjs <input.html> <output.pdf>
const { chromium } = require('playwright');
const { pathToFileURL } = require('node:url');
const path = require('node:path');

const [, , input, output] = process.argv;
if (!input || !output) {
  console.error('usage: node print_pdf.cjs <input.html> <output.pdf>');
  process.exit(2);
}

(async () => {
const browser = await chromium.launch();
const page = await browser.newPage();
await page.goto(pathToFileURL(path.resolve(input)).href, { waitUntil: 'load' });
await page.pdf({
  path: output,
  format: 'A4',
  printBackground: true,
  displayHeaderFooter: true,
  margin: { top: '18mm', bottom: '18mm', left: '16mm', right: '16mm' },
  headerTemplate:
    '<div style="font-size:7px;color:#666;width:100%;padding:0 16mm;font-family:Helvetica,Arial,sans-serif;">' +
    '<span>GnB-SMH Code Audit &mdash; Comparative Analysis vs Bitcoin Core</span>' +
    '<span style="float:right">Commit 125e9e5 &middot; 2026-10-14</span></div>',
  footerTemplate:
    '<div style="font-size:7px;color:#666;width:100%;padding:0 16mm;font-family:Helvetica,Arial,sans-serif;">' +
    '<span>Code-only assessment. No hashrate, adoption or market assumptions.</span>' +
    '<span style="float:right">Page <span class="pageNumber"></span> of <span class="totalPages"></span></span></div>',
});
await browser.close();
console.log('wrote', output);
})();
