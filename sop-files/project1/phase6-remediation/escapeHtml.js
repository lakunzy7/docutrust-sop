/**
 * Escapes the five characters that carry structural meaning in HTML, so a
 * value can be placed into a document as text rather than as markup.
 *
 * Used by the render endpoint in routes/documents.js. That endpoint writes
 * a document's title and body into an HTML response; without this, a title
 * containing a <script> tag is delivered to the browser as a script tag,
 * and the browser runs it. The data does not change -- what changes is that
 * the browser is told to treat it as text.
 *
 * Deliberately hand-written rather than pulled from npm. escape-html is a
 * six-line function with no dependencies, and adding a package would put a
 * dependency into DocuTrust's tree that Project 1 introduced rather than the
 * application -- which is Project 2's subject, and its measurement baseline.
 *
 * The ORDER of the replacements is load-bearing. Ampersand must be escaped
 * first: every replacement below introduces an "&" of its own, so escaping
 * it last would turn this function's own output into "&amp;lt;" and render
 * literal "&lt;" on the page. Wrong in a way that looks like it works.
 */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

module.exports = { escapeHtml };
