# Editor support for Chai

Syntax highlighting for the Chai policy language (`.chai` files) across editors and
the web. All four share one token model: comments (`#`), strings, effects
(`permit`/`forbid`/`deny`/`redact`/`defer`/`downgrade`/`require_human`), the mode
directive (`mode first_match` / `mode deny_override`), word operators
(`and`/`or`/`not`/`in`/`has`/`contains`/`like`/`is`), fact roots (`dlp_facts`,
`tooltrace`, ...), entity literals (`User::"alice"`), annotations (`@id("...")`),
and template slots (`?principal`).

## VS Code

A minimal extension in [`vscode/`](vscode/). To try it locally, copy the folder
into your extensions directory and reload:

```sh
cp -r vscode ~/.vscode/extensions/chai-policy-0.1.0
```

It contributes the `chai` language for `.chai` files, a TextMate grammar
([`vscode/syntaxes/chai.tmLanguage.json`](vscode/syntaxes/chai.tmLanguage.json)),
and comment/bracket behavior. To publish it, run `vsce package` in `vscode/`.

## Vim / Neovim

Files in [`vim/`](vim/):

```sh
mkdir -p ~/.vim/syntax ~/.vim/ftdetect
cp vim/syntax/chai.vim   ~/.vim/syntax/
cp vim/ftdetect/chai.vim ~/.vim/ftdetect/
```

Or point a plugin manager at this `vim/` directory. Opening any `.chai` file then
highlights automatically.

## highlight.js (web, docs, playground)

[`highlightjs/chai.js`](highlightjs/chai.js) registers `chai` with highlight.js:

```js
import hljs from 'highlight.js/lib/core';
import chai from './chai.js';
hljs.registerLanguage('chai', chai);
hljs.highlightAll();
```

Then any `<pre><code class="language-chai">` block is highlighted. This is the
definition to drop into the browser playground or a docs site.

## TextMate grammar

`vscode/syntaxes/chai.tmLanguage.json` is a standard TextMate grammar
(`scopeName: source.chai`). Anything that consumes TextMate grammars (Sublime
Text, the `bat` pager, GitHub's Linguist via a submission) can reuse it directly.
