" .api batch files of the CommerceOS API client
if exists('b:did_ftplugin')
  finish
endif
let b:did_ftplugin = 1

setlocal commentstring=#\ %s
setlocal comments=:#
setlocal omnifunc=ApiComplete
" `gq` lays out what it is given as the client does (`api --format`): `gggqG`
" for the whole file. A motion that cuts a body in two is left as it is.
let &l:formatprg = shellescape(get(g:, 'api_binary', 'api')) . ' --format -'
" :ApiFormat lays the whole file out and leaves the cursor where it is;
" :ApiFormat! gives every member of an object or an array a line.
command! -buffer -bang ApiFormat call ApiFormat(<bang>0)

let b:undo_ftplugin = 'setlocal commentstring< comments< omnifunc< formatprg< | delcommand ApiFormat'

if exists('*ApiComplete')
  finish
endif

" Omni completion (ctrl+x ctrl+o): what can stand where the cursor is, is the
" client's to say. It is asked (`api --complete`) with the text of the buffer
" and the bytes in front of the cursor. `g:api_binary` names another client
" than the `api` on the PATH.
function! ApiComplete(findstart, base) abort
  if a:findstart
    let s:items = []
    let l:before = getline(1, line('.') - 1)
    let l:at = len(join(l:before, "\n")) + (empty(l:before) ? 0 : 1) + col('.') - 1
    let l:file = expand('%:p')
    let l:command = shellescape(get(g:, 'api_binary', 'api')) . ' -r --complete '
          \ . shellescape(empty(l:file) ? '-' : l:file) . ' --at ' . l:at
    silent let l:answer = system(l:command, join(getline(1, '$'), "\n"))
    if v:shell_error
      return -3
    endif
    try
      let l:result = json_decode(l:answer)
    catch
      return -3
    endtry
    if type(l:result) != type({}) || !has_key(l:result, 'items')
      return -3
    endif
    let s:items = l:result.items
    return col('.') - 1 - strlen(l:result.typed)
  endif
  let l:matches = []
  for l:item in s:items
    if stridx(tolower(l:item.name), tolower(a:base)) == 0
      call add(l:matches, {'word': l:item.text, 'abbr': l:item.name, 'menu': l:item.note})
    endif
  endfor
  return l:matches
endfunction

" The whole buffer as the client lays a `.api` file out. A client that
" can't be asked (one from before `--format`) changes nothing.
function! ApiFormat(expanded) abort
  let l:command = shellescape(get(g:, 'api_binary', 'api')) . ' --format -' . (a:expanded ? ' --expand' : '')
  let l:text = join(getline(1, '$'), "\n") . "\n"
  silent let l:answer = system(l:command, l:text)
  if v:shell_error
    echohl WarningMsg | echo 'api --format failed: it needs a client that has it' | echohl None
    return
  endif
  if l:answer ==# l:text
    return
  endif
  let l:view = winsaveview()
  let l:lines = split(l:answer, "\n", 1)
  if !empty(l:lines) && l:lines[-1] ==# ''
    call remove(l:lines, -1)
  endif
  silent! undojoin
  if len(l:lines) < line('$')
    silent execute (len(l:lines) + 1) . ',$delete _'
  endif
  call setline(1, l:lines)
  call winrestview(l:view)
endfunction
