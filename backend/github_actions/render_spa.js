/**
 * ==============================================================================
 * 10blackfingers - SPA Renderer (Puppeteer Automation)
 * Fully automated headless browser rendering for Single Page Applications.
 * ==============================================================================
 */

const puppeteer = require('puppeteer');
const fs = require('fs');
const path = require('path');

async function renderPage() {
    const targetUrl = process.argv[2];
    const outputPath = process.argv[3] || path.join(__dirname, 'rendered_output.html');

    if (!targetUrl) {
        console.error('[-] Error: Target URL is required as an argument.');
        process.exit(1);
    }

    console.log(`[+] Launching headless browser for SPA rendering: ${targetUrl}`);

    let browser;
    try {
        browser = await puppeteer.launch({
            headless: 'new',
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-accelerated-2d-canvas',
                '--disable-gpu',
                '--no-zygote',
                '--single-process'
            ]
        });

        const page = await browser.newPage();
        
        // Set viewport and professional penetration testing user agent
        await page.setViewport({ width: 1366, height: 768 });
        await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 10blackfingers-Scanner');

        // Enable request interception and logging if needed
        page.on('console', msg => {
            if (msg.type() === 'error') {
                console.log(`[Browser Console Error]: ${msg.text()}`);
            }
        });

        console.log(`[+] Navigating to target URL with timeout limits...`);
        await page.goto(targetUrl, {
            waitUntil: 'networkidle2',
            timeout: 60000
        });

        // Wait additional time for client-side hydration, AJAX calls, and DOM rendering
        console.log(`[+] Waiting for DOM hydration and dynamic script execution...`);
        await new Promise(resolve => setTimeout(resolve, 6000));

        // Extract fully rendered HTML content
        const htmlContent = await page.content();

        // Ensure output directory exists
        const dir = path.dirname(outputPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        // Save rendered HTML to disk
        fs.writeFileSync(outputPath, htmlContent, 'utf8');
        console.log(`[+] Successfully rendered SPA target and saved output to: ${outputPath}`);

    } catch (error) {
        console.error(`[-] Fatal Error during Puppeteer SPA rendering: ${error.message}`);
        process.exit(1);
    } finally {
        if (browser) {
            await browser.close();
            console.log(`[+] Browser instance closed safely.`);
        }
    }
}

renderPage();