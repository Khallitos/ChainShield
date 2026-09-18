/** Render README plain text into structured sections */
export default function ReadmeContent({ text, packageName }) {
  if (!text?.trim()) return null;

  const blocks = parseReadme(normalizeReadmeText(text));

  return (
    <article className="readme-doc">
      {blocks.map((block, i) => {
        if (block.type === "heading") {
          return (
            <h3 key={i} className={`readme-h readme-h-${block.level}`}>
              {block.text}
            </h3>
          );
        }
        if (block.type === "code") {
          return (
            <pre key={i} className="readme-code">
              <code>{highlightCode(block.text)}</code>
            </pre>
          );
        }
        if (block.type === "list") {
          return (
            <ul key={i} className="readme-list">
              {block.items.map((item, j) => (
                <li key={j}>{item}</li>
              ))}
            </ul>
          );
        }
        if (block.type === "hr") {
          return <hr key={i} className="readme-hr" />;
        }
        return (
          <p key={i} className="readme-p">
            {formatInline(block.text)}
          </p>
        );
      })}
    </article>
  );
}

function parseReadme(text) {
  const lines = text.split("\n");
  const blocks = [];
  let i = 0;
  let inCode = false;
  let codeBuf = [];

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim().startsWith("```")) {
      if (inCode) {
        blocks.push({ type: "code", text: codeBuf.join("\n") });
        codeBuf = [];
        inCode = false;
      } else {
        inCode = true;
      }
      i += 1;
      continue;
    }

    if (inCode) {
      codeBuf.push(line);
      i += 1;
      continue;
    }

    if (/^ {4}\S/.test(line)) {
      const codeLines = [];
      while (i < lines.length && /^ {4}/.test(lines[i])) {
        codeLines.push(lines[i].replace(/^ {4}/, ""));
        i += 1;
      }
      blocks.push({ type: "code", text: codeLines.join("\n") });
      continue;
    }

    if (/^#{1,4}\s+/.test(line)) {
      const level = line.match(/^#+/)[0].length;
      blocks.push({ type: "heading", level: Math.min(level, 3), text: line.replace(/^#+\s*/, "") });
      i += 1;
      continue;
    }

    if (/^[-*]\s+/.test(line.trim())) {
      const items = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^[-*]\s+/, ""));
        i += 1;
      }
      blocks.push({ type: "list", items });
      continue;
    }

    if (/^---+$/.test(line.trim()) || /^\*\*\*+$/.test(line.trim())) {
      blocks.push({ type: "hr" });
      i += 1;
      continue;
    }

    if (line.trim()) {
      let para = line;
      i += 1;
      while (i < lines.length && lines[i].trim() && !/^#/.test(lines[i]) && !/^[-*]\s+/.test(lines[i].trim())) {
        para += ` ${lines[i].trim()}`;
        i += 1;
      }
      blocks.push({ type: "paragraph", text: para });
      continue;
    }

    i += 1;
  }

  if (codeBuf.length) {
    blocks.push({ type: "code", text: codeBuf.join("\n") });
  }

  return blocks.length ? blocks : [{ type: "paragraph", text }];
}

function formatInline(text) {
  const parts = text.split(/(`[^`]+`)/g);
  return parts.map((part, i) => {
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code key={i} className="readme-inline-code">
          {part.slice(1, -1)}
        </code>
      );
    }
    return part;
  });
}

const CODE_KEYWORDS =
  /\b(import|export|default|from|const|let|var|function|return|if|else|for|while|class|extends|new|async|await|typeof|require|module|npm|yarn|pip|install|use|def|print|true|false|null|undefined|void|public|private|static|interface|type|enum|switch|case|break|try|catch|throw|finally|package|include|using|namespace)\b/g;

function highlightCode(source) {
  const tokens = [];
  let last = 0;
  const matches = [];

  for (const match of source.matchAll(CODE_KEYWORDS)) {
    matches.push({ start: match.index, end: match.index + match[0].length, kind: "kw", text: match[0] });
  }
  for (const match of source.matchAll(/('(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"|`(?:\\.|[^`\\])*`)/g)) {
    matches.push({ start: match.index, end: match.index + match[0].length, kind: "str", text: match[0] });
  }
  for (const match of source.matchAll(/(#.*$|\/\/.*$|\/\*[\s\S]*?\*\/)/gm)) {
    matches.push({ start: match.index, end: match.index + match[0].length, kind: "comment", text: match[0] });
  }

  matches.sort((a, b) => a.start - b.start || b.end - a.end - (a.end - a.start));

  const used = [];
  for (const m of matches) {
    if (used.some((u) => m.start < u.end && m.end > u.start)) continue;
    used.push(m);
    if (m.start > last) tokens.push(<span key={`t-${last}`}>{source.slice(last, m.start)}</span>);
    const cls =
      m.kind === "kw" ? "readme-code-kw" : m.kind === "str" ? "readme-code-str" : "readme-code-comment";
    tokens.push(
      <span key={`m-${m.start}`} className={cls}>
        {m.text}
      </span>
    );
    last = m.end;
  }

  if (last < source.length) tokens.push(<span key={`t-${last}`}>{source.slice(last)}</span>);
  return tokens.length ? tokens : source;
}

function normalizeReadmeText(text) {
  if (!text?.trim()) return text;
  if (!/<[a-z][^>]*>/i.test(text)) return text.replace(/\r\n/g, "\n");

  let html = text.replace(/\r\n/g, "\n");
  html = html.replace(
    /<pre[^>]*>\s*(?:<code[^>]*>)?([\s\S]*?)(?:<\/code>\s*)?<\/pre>/gi,
    (_, code) => `\n\`\`\`\n${decodeHtml(stripTags(code)).trim()}\n\`\`\`\n`
  );
  html = html.replace(
    /<h([1-4])[^>]*>([\s\S]*?)<\/h\1>/gi,
    (_, level, inner) => `\n${"#".repeat(Number(level))} ${decodeHtml(stripTags(inner)).trim()}\n`
  );
  html = html.replace(/<li[^>]*>([\s\S]*?)<\/li>/gi, (_, inner) => `\n- ${decodeHtml(stripTags(inner)).trim()}`);
  html = html.replace(/<br\s*\/?>/gi, "\n");
  html = html.replace(/<\/p>/gi, "\n\n");
  html = html.replace(/<hr\s*\/?>/gi, "\n---\n");
  html = html.replace(/<code[^>]*>([\s\S]*?)<\/code>/gi, (_, inner) => `\`${decodeHtml(stripTags(inner))}\``);
  html = decodeHtml(stripTags(html));
  return html.replace(/\n{3,}/g, "\n\n").trim();
}

function stripTags(value) {
  return value.replace(/<[^>]+>/g, "");
}

function decodeHtml(value) {
  return value
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
}
