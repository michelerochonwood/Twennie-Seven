// utils/csv.js
function escapeCsv(val) {
  if (val === null || val === undefined) return '';
  const s = String(val);
  // Quote if contains comma, quote, or newline
  if (/[",\n]/.test(s)) return `"${s.replace(/"/g, '""')}"`;
  return s;
}

/**
 * rows: Array of plain objects
 * columns: Array of { key, header } determining column order and labels
 * returns UTF-8 string with BOM so Excel opens cleanly
 */
function toCSV(rows, columns) {
  const head = columns.map(c => escapeCsv(c.header)).join(',');
  const body = rows.map(r =>
    columns.map(c => escapeCsv(r[c.key])).join(',')
  ).join('\n');

  // BOM helps Excel recognize UTF-8
  return '\uFEFF' + head + '\n' + body + '\n';
}

module.exports = { toCSV };
