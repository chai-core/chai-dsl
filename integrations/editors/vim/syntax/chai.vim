" Vim syntax file for the Chai policy language (chai_dsl).
" Install: copy to ~/.vim/syntax/chai.vim and the ftdetect file to
" ~/.vim/ftdetect/chai.vim (or use a plugin manager pointing at this directory).

if exists("b:current_syntax")
  finish
endif

syn keyword chaiEffect     permit forbid deny redact defer downgrade require_human
syn keyword chaiMode       mode first_match deny_override
syn keyword chaiKeyword    when from to action any obligations
syn keyword chaiPam        required requisite sufficient optional
syn keyword chaiOperator   and or not in has contains like is
syn keyword chaiBool       true false
syn keyword chaiFunc       ip decimal size len containsAll containsAny
syn keyword chaiRoot       principal action resource subject object context args
syn keyword chaiRoot       dlp_facts safety_facts grounding_facts schema_facts
syn keyword chaiRoot       tooltrace risk_facts thresholds

syn match   chaiComment    "#.*$"
syn region  chaiString     start=+"+ end=+"+
syn match   chaiNumber     "\<-\=\d\+\(\.\d\+\)\=\>"
syn match   chaiEntity     "\<[A-Za-z_]\w*\(::[A-Za-z_]\w*\)*::"
syn match   chaiAnnotation "@\w\+"
syn match   chaiSlot       "?\w\+"
syn match   chaiField      "\.\w\+"
syn match   chaiCompare    "==\|!=\|<=\|>=\|<\|>\|&&\|||\|!"

hi def link chaiEffect     Keyword
hi def link chaiMode       PreProc
hi def link chaiKeyword    Statement
hi def link chaiPam        Statement
hi def link chaiOperator   Operator
hi def link chaiBool       Boolean
hi def link chaiFunc       Function
hi def link chaiRoot       Identifier
hi def link chaiComment    Comment
hi def link chaiString     String
hi def link chaiNumber     Number
hi def link chaiEntity     Type
hi def link chaiAnnotation PreProc
hi def link chaiSlot       Special
hi def link chaiField      Identifier
hi def link chaiCompare    Operator

let b:current_syntax = "chai"
