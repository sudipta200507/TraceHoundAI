/** Minimal safe Markdown renderer: escapes HTML first, supports headings,
 * bold, inline code, links (http/https only), lists, tables, and paragraphs.
 * Raw HTML from report content is never injected.
 */

function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

function inline(text) {
  let out = escapeHtml(text)
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>')
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
  out = out.replace(
    /\[([^\]]+)\]\((https?:\/\/[^)\s]+|(?:\.\.\/)+[^\s)]+)\)/g,
    '<a href="$2" rel="noreferrer">$1</a>',
  )
  return out
}

function isTableRow(line) {
  return /^\|.*\|\s*$/.test(line.trim())
}

function renderTable(lines) {
  const rows = lines.map((line) =>
    line
      .trim()
      .replace(/^\||\|$/g, '')
      .split('|')
      .map((cell) => cell.trim()),
  )
  const body = rows.filter((_, index) => index !== 1)
  const head = body[0]
  const rest = body.slice(1)
  let html = '<table><thead><tr>'
  for (const cell of head) html += `<th>${inline(cell)}</th>`
  html += '</tr></thead><tbody>'
  for (const row of rest) {
    html += '<tr>'
    for (const cell of row) html += `<td>${inline(cell)}</td>`
    html += '</tr>'
  }
  return `${html}</tbody></table>`
}

export function renderMarkdown(markdown) {
  const lines = String(markdown || '').split('\n')
  let html = ''
  let i = 0
  let listOpen = false
  const closeList = () => {
    if (listOpen) {
      html += '</ul>'
      listOpen = false
    }
  }
  while (i < lines.length) {
    const line = lines[i]
    if (isTableRow(line)) {
      const group = []
      while (i < lines.length && isTableRow(lines[i])) {
        group.push(lines[i])
        i += 1
      }
      closeList()
      html += renderTable(group)
      continue
    }
    const heading = /^(#{1,4})\s+(.*)$/.exec(line)
    if (heading) {
      closeList()
      const level = heading[1].length
      html += `<h${level}>${inline(heading[2])}</h${level}>`
    } else if (/^\s*-\s+/.test(line)) {
      if (!listOpen) {
        html += '<ul>'
        listOpen = true
      }
      html += `<li>${inline(line.replace(/^\s*-\s+/, ''))}</li>`
    } else if (/^\s*>\s?/.test(line)) {
      closeList()
      html += `<blockquote>${inline(line.replace(/^\s*>\s?/, ''))}</blockquote>`
    } else if (line.trim() === '') {
      closeList()
    } else {
      closeList()
      html += `<p>${inline(line)}</p>`
    }
    i += 1
  }
  closeList()
  return html
}
