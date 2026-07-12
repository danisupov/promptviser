// Example JavaScript caller file for pass3 AST testing.
// References a prompt file by name — findCallerFiles will detect this.
// TODO: AST visitor should flag template literal construction risks.
const fs = require('fs');

function loadPrompt() {
  return fs.readFileSync('prompts/rag-search.yaml', 'utf8');
}

module.exports = { loadPrompt };
