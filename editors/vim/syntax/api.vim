" Vim syntax for .api batch files of the CommerceOS API client.
" Follows editors/sublime/API.sublime-syntax, which follows AGENTS.md. It
" colours what a line is; unlike the Sublime and TextMate grammars it does
" not mark what would stop a batch. Check a change against editors/sample.api.

if exists('b:current_syntax')
  finish
endif

" Where two items match at the same place the one defined last wins, so the
" order below goes from the general to the particular.

" ---------------------------------------------------------------- JSON bodies

syn match  apiJsonNumber  /-\=\<\d\+\%(\.\d\+\)\=\%([eE][+-]\=\d\+\)\=\>/ contained
syn match  apiJsonConst   /\<\%(true\|false\|null\)\>/ contained
syn region apiJsonString  start=/"/ skip=/\\./ end=/"/ contained
syn match  apiJsonKey     /"\%(\\.\|[^"\\]\)*"\ze\s*:/ contained
syn match  apiJsonComment /\/\/.*$/ contained
syn match  apiJsonComment /#.*$/ contained
syn region apiJsonComment start=/\/\*/ end=/\*\// contained
syn region apiJsonObject  matchgroup=apiBrace start=/{/ end=/}/ contained contains=@apiJson
syn region apiJsonArray   matchgroup=apiBrace start=/\[/ end=/\]/ contained contains=@apiJson
syn cluster apiJson contains=apiJsonNumber,apiJsonConst,apiJsonString,apiJsonKey,apiJsonComment,apiJsonObject,apiJsonArray

" ------------------------------------------------------ the parts of a request

" what may follow a URI, a body or a path on the same line
syn cluster apiTail contains=apiRedirect,apiChain,apiTrailComment

syn match  apiTrailComment /\s\@1<=#.*$/ contained

" The braces of a region are a group of their own (matchgroup), so that a
" nested object can't start on the brace that opened its parent.

" a URI: up to the next blank, with the parentheses of an operator kept whole
syn match  apiUri /\%([^[:space:](]\|([^)]*)\)\+/ contained contains=apiUriString,apiUriPunct nextgroup=apiBodyObject,apiBodyArray,apiBodyString,apiInfile,@apiTail skipwhite
syn match  apiUriPunct  /[\/~(){}:?#=&@.;,<>+*!|-]/ contained
syn region apiUriString start=/"/ end=/"\|$/ contained oneline

syn region apiBodyObject matchgroup=apiBrace start=/{/ end=/}/ contained contains=@apiJson nextgroup=@apiTail skipwhite
syn region apiBodyArray  matchgroup=apiBrace start=/\[/ end=/\]/ contained contains=@apiJson nextgroup=@apiTail skipwhite
syn region apiBodyString start=/"/ skip=/\\./ end=/"/ contained oneline nextgroup=@apiTail skipwhite

syn match  apiInfile /@\s*\S*/ contained contains=apiInfileOp,apiMap,apiWildcard nextgroup=@apiTail skipwhite
syn match  apiInfileOp /@/ contained
syn match  apiMap /\~map\ze(/ contained
syn match  apiWildcard /[*?]/ contained

syn match  apiRedirect /\s\@1<=>>\=/ contained nextgroup=apiOutfile,apiClipboard skipwhite
syn match  apiOutfile /\S\+/ contained nextgroup=apiChain,apiTrailComment skipwhite
syn match  apiClipboard /\cclipboard\ze\%(\s\|$\)/ contained nextgroup=apiChain,apiTrailComment skipwhite

" `&&` / `||`, and the request behind one
syn match  apiChain /&&\|||/ contained nextgroup=apiUri,apiSegRead,apiSegWrite,apiSegDelete skipwhite
syn match  apiSegRead   /\c\%(GET\|HEAD\|OPTIONS\)\ze\%(\s\|$\)/ contained nextgroup=apiUri skipwhite
syn match  apiSegWrite  /\c\%(PUT\|POST\|PATCH\)\ze\%(\s\|$\)/ contained nextgroup=apiUri skipwhite
syn match  apiSegDelete /\cDELETE\ze\%(\s\|$\)/ contained nextgroup=apiUri skipwhite

" --------------------------------------------------------------------- lines

" anything that is nothing else is an include
syn match  apiInclude /^\s*\zs[^[:space:]#{\[].\{-}\ze\s*\%(\s#.*\)\=$/ contains=apiWildcard nextgroup=apiTrailComment skipwhite

" `/people` is `GET /people`; `/tmp/seed.api` is an include
syn match  apiImpliedUri /^\s*\zs\/\%([^[:space:](]\|([^)]*)\)*/ contains=apiUriString,apiUriPunct nextgroup=apiBodyObject,apiBodyArray,apiBodyString,apiInfile,@apiTail skipwhite
syn match  apiInclude /^\s*\zs\/\S*\c\.api\ze\s*\%(\s#.*\)\=$/ contains=apiWildcard nextgroup=apiTrailComment skipwhite

syn match  apiMethodRead   /^\s*\zs\c\%(GET\|HEAD\|OPTIONS\)\ze\%(\s\|$\)/ nextgroup=apiUri skipwhite
syn match  apiMethodWrite  /^\s*\zs\c\%(PUT\|POST\|PATCH\)\ze\%(\s\|$\)/ nextgroup=apiUri skipwhite
syn match  apiMethodDelete /^\s*\zs\cDELETE\ze\%(\s\|$\)/ nextgroup=apiUri skipwhite

" url has <text> / url is <url>
syn match  apiDirective /^\s*\zs\curl\ze\%(\s\|$\)/ nextgroup=apiUrlOp skipwhite
syn match  apiUrlOp /\c\%(has\|is\)\ze\%(\s\|$\)/ contained nextgroup=apiValue skipwhite
syn match  apiValue /\S\+/ contained nextgroup=apiTrailComment skipwhite

" sleep N / sleep [N] while [not] <request> / assert [not] <request>
syn match  apiDirective /^\s*\zs\csleep\ze\%(\s\|$\)/ nextgroup=apiDuration,apiWhile,apiTrailComment skipwhite
syn match  apiDuration /\d*\.\=\d\+\%(ms\|s\)\=\ze\%(\s\|$\)/ contained nextgroup=apiWhile,apiTrailComment skipwhite
syn match  apiWhile /\cwhile\ze\%(\s\|$\)/ contained nextgroup=apiUri,apiNot,apiSegRead,apiSegWrite,apiSegDelete skipwhite
syn match  apiDirective /^\s*\zs\cassert\ze\%(\s\|$\)/ nextgroup=apiUri,apiNot,apiSegRead,apiSegWrite,apiSegDelete skipwhite
syn match  apiNot /\cnot\ze\%(\s\|$\)/ contained nextgroup=apiUri,apiSegRead,apiSegWrite,apiSegDelete skipwhite

" confirm [message]: all of the line is the question
syn match  apiDirective /^\s*\zs\cconfirm\ze\%(\s\|$\)/ nextgroup=apiMessage skipwhite
syn match  apiMessage /.*$/ contained

" set { … }  or  set @file.json
syn match  apiDirective /^\s*\zs\cset\ze\%(\s\|$\)/ nextgroup=apiBodyObject,apiInfile skipwhite

" import git|dir|archive <alias> { … }  or  … @file.json
syn match  apiImport /^\s*\zs\cimport\ze\%(\s\|$\)/ nextgroup=apiImportKind skipwhite
syn match  apiImportKind /\c\%(git\|dir\|archive\)\ze\%(\s\|$\)/ contained nextgroup=apiAlias skipwhite
syn match  apiAlias /[A-Za-z0-9_-]\+/ contained nextgroup=apiBodyObject,apiInfile skipwhite

" a describe block: a `{` that starts a line
syn region apiDescribe matchgroup=apiBrace start=/^\s*{/ end=/}/ contains=@apiJson

syn match  apiComment /^\s*#.*$/

" -------------------------------------------------------------------- colours

hi def link apiComment      Comment
hi def link apiTrailComment Comment
hi def link apiJsonComment  Comment
hi def link apiMethodRead   Statement
hi def link apiMethodWrite  Statement
hi def link apiMethodDelete Statement
hi def link apiSegRead      apiMethodRead
hi def link apiSegWrite     apiMethodWrite
hi def link apiSegDelete    apiMethodDelete
hi def link apiDirective    PreProc
hi def link apiImport       PreProc
hi def link apiWhile        Conditional
hi def link apiNot          Conditional
hi def link apiUrlOp        Operator
hi def link apiChain        Operator
hi def link apiRedirect     Operator
hi def link apiInfileOp     Operator
hi def link apiUriPunct     Delimiter
hi def link apiBrace        Delimiter
hi def link apiUriString    String
hi def link apiWildcard     Special
hi def link apiClipboard    Special
hi def link apiMap          Function
hi def link apiOutfile      Directory
hi def link apiInfile       Directory
hi def link apiInclude      Include
hi def link apiValue        String
hi def link apiMessage      String
hi def link apiBodyString   String
hi def link apiDuration     Number
hi def link apiImportKind   Type
hi def link apiAlias        Identifier
hi def link apiJsonKey      Label
hi def link apiJsonString   String
hi def link apiJsonNumber   Number
hi def link apiJsonConst    Boolean

" A body and a describe block span lines: read from the top, so that a jump
" into the middle of one does not take its lines for lines of their own.
syn sync fromstart

let b:current_syntax = 'api'
