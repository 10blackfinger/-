// backend/github_actions/render_spa.js
// يستخدم Puppeteer عشان يفتح الموقع فعليًا في متصفح headless
// وياخد الـ HTML بعد ما الـ JavaScript framework (React/Angular/Vue) يخلص تنفيذ،
// ويستخرج كل الروابط الحقيقية الظاهرة بعد الـ render.

const puppeteer = require('puppeteer');
const fs = require('fs');

(async () => {
    const targetUrl = process.argv[2];
    const outputPath = process.argv[3];

    if (!targetUrl || !outputPath) {
        console.error('Usage: node render_spa.js <target_url> <output_path>');
        process.exit(1);
    }

    let browser;
    try {
        browser = await puppeteer.launch({
            headless: 'new',
            args: ['--no-sandbox', '--disable-setuid-sandbox'],
        });

        const page = await browser.newPage();
        await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 30000 });

        const renderedHTML = await page.content();

        const links = await page.evaluate(() =>
            Array.from(document.querySelectorAll('a[href]')).map((a) => a.href)
        );

        fs.writeFileSync(
            outputPath,
            JSON.stringify({ html: renderedHTML.slice(0, 20000), links }, null, 2)
        );

        console.log(`تم استخراج ${links.length} رابط من الموقع بعد الـ render`);
    } catch (err) {
        console.error(`خطأ: ${err.message}`);
        // نكتب ملف فاضي عشان الكود البايثون ميفشلش لو الفحص فشل
        try {
            fs.writeFileSync(outputPath, JSON.stringify({ html: '', links: [] }));
        } catch (_) {}
        process.exit(0);
    } finally {
        if (browser) await browser.close();
    }
})();