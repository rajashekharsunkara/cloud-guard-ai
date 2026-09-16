import { inlineMarkdown } from "./util.js";

// Just enough Markdown for model-written reports: headings, lists, bold, code.
export function renderMarkdown(source) {
  const out = [];
  let list = null;
  const closeList = () => {
    if (list) {
      out.push(`</${list}>`);
      list = null;
    }
  };

  String(source || "").split("\n").forEach((raw) => {
    const line = raw.trimEnd();
    const heading = line.match(/^#{1,6}\s+(.*)$/);
    const bullet = line.match(/^\s*[-*]\s+(.*)$/);
    const numbered = line.match(/^\s*(\d+)[.)]\s+(.*)$/);

    if (heading) {
      closeList();
      out.push(`<h3>${inlineMarkdown(heading[1])}</h3>`);
    } else if (bullet || numbered) {
      const tag = bullet ? "ul" : "ol";
      if (list !== tag) {
        closeList();
        // Keep the numbering when bullets interrupt a numbered list.
        out.push(numbered ? `<ol start="${Number(numbered[1])}">` : "<ul>");
        list = tag;
      }
      out.push(`<li>${inlineMarkdown(bullet ? bullet[1] : numbered[2])}</li>`);
    } else if (line.trim() === "" || /^-{3,}$/.test(line.trim())) {
      closeList();
    } else {
      closeList();
      out.push(`<p>${inlineMarkdown(line)}</p>`);
    }
  });
  closeList();
  return out.join("");
}
