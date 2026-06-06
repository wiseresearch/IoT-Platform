const fs = require('fs');
const path = require('path');

function escapeHtml(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function inlineFormat(text) {
  let out = escapeHtml(text);
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  return out;
}

function renderBody(lines) {
  const html = [];
  let inCode = false;
  let codeBuffer = [];
  let listType = null;

  function closeList() {
    if (listType) {
      html.push(`</${listType}>`);
      listType = null;
    }
  }

  function flushCode() {
    if (!inCode) return;
    html.push(`<pre class="code-block">${escapeHtml(codeBuffer.join('\n'))}</pre>`);
    inCode = false;
    codeBuffer = [];
  }

  for (const rawLine of lines) {
    const line = rawLine.replace(/\r$/, '');
    const trimmed = line.trim();

    if (trimmed.startsWith('```')) {
      if (inCode) {
        flushCode();
      } else {
        closeList();
        inCode = true;
      }
      continue;
    }

    if (inCode) {
      codeBuffer.push(line);
      continue;
    }

    if (!trimmed) {
      closeList();
      continue;
    }

    if (trimmed === '---') {
      closeList();
      continue;
    }

    if (/^[-*]\s+/.test(trimmed)) {
      if (listType !== 'ul') {
        closeList();
        listType = 'ul';
        html.push('<ul>');
      }
      html.push(`<li>${inlineFormat(trimmed.replace(/^[-*]\s+/, ''))}</li>`);
      continue;
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      if (listType !== 'ol') {
        closeList();
        listType = 'ol';
        html.push('<ol>');
      }
      html.push(`<li>${inlineFormat(trimmed.replace(/^\d+\.\s+/, ''))}</li>`);
      continue;
    }

    closeList();

    if (/^###\s+/.test(trimmed)) {
      html.push(`<h3>${inlineFormat(trimmed.replace(/^###\s+/, ''))}</h3>`);
      continue;
    }

    html.push(`<p>${inlineFormat(trimmed)}</p>`);
  }

  closeList();
  flushCode();
  return html.join('\n');
}

function buildHtml(markdown, titleOverride) {
  const normalized = markdown.replace(/\r\n/g, '\n');
  const firstH1 = normalized.match(/^#\s+(.+)$/m);
  const docTitle = titleOverride || (firstH1 ? firstH1[1].trim() : 'Presentation');

  const parts = normalized.split(/\n(?=##\s+)/g);
  const preamble = parts.shift() || '';
  const slides = parts;

  const preambleLines = preamble
    .split('\n')
    .filter((l) => l.trim() && !l.trim().startsWith('#'))
    .map((l) => `<p class="subtitle">${inlineFormat(l.trim())}</p>`)
    .join('\n');

  const slideHtml = slides.map((chunk) => {
    const lines = chunk.split('\n');
    const firstLine = lines.shift() || '';
    const heading = firstLine.replace(/^##\s+/, '').trim();
    const body = renderBody(lines);
    return `<section class="slide"><h2>${inlineFormat(heading)}</h2>${body}</section>`;
  }).join('\n');

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(docTitle)}</title>
  <style>
    @page { size: A4 landscape; margin: 18mm; }
    body { font-family: "Segoe UI", Arial, sans-serif; color: #1f2937; margin: 0; background: #fff; }
    .cover { min-height: 100vh; display: flex; flex-direction: column; justify-content: center; page-break-after: always; }
    .cover h1 { font-size: 46px; margin: 0 0 12px 0; color: #0f172a; }
    .subtitle { font-size: 20px; color: #334155; margin: 6px 0; }
    .slide { min-height: calc(100vh - 10mm); page-break-after: always; }
    .slide h2 { font-size: 34px; margin: 0 0 18px 0; color: #0b3a70; border-bottom: 3px solid #dbeafe; padding-bottom: 8px; }
    h3 { font-size: 24px; margin: 14px 0 10px 0; color: #1e3a8a; }
    p, li { font-size: 22px; line-height: 1.45; }
    ul, ol { margin: 8px 0 14px 24px; }
    code { font-family: Consolas, monospace; background: #f1f5f9; padding: 1px 6px; border-radius: 4px; font-size: 90%; }
    .code-block { font-family: Consolas, monospace; font-size: 14px; line-height: 1.35; background: #0f172a; color: #e2e8f0; padding: 12px; border-radius: 8px; white-space: pre-wrap; }
    a { color: #1d4ed8; text-decoration: none; }
    strong { color: #111827; }
  </style>
</head>
<body>
  <section class="cover">
    <h1>${escapeHtml(docTitle)}</h1>
    ${preambleLines}
  </section>
  ${slideHtml}
</body>
</html>`;
}

function main() {
  const input = process.argv[2];
  const output = process.argv[3];
  const title = process.argv[4];
  if (!input || !output) {
    console.error('Usage: node scripts/render_markdown_presentation.js <input.md> <output.html> [title]');
    process.exit(1);
  }
  const src = fs.readFileSync(path.resolve(input), 'utf8');
  const html = buildHtml(src, title);
  fs.writeFileSync(path.resolve(output), html, 'utf8');
  console.log(`HTML generated: ${output}`);
}

main();
