# bash completion for juist. The candidates come from juist itself
# ("juist __complete"), so they follow the commands and options it has.
_juist() {
	local words cword
	# Keys (nid:…) and --option=value are one word to juist, whatever
	# COMP_WORDBREAKS says; bash-completion's helper joins them back.
	if declare -F _get_comp_words_by_ref >/dev/null; then
		_get_comp_words_by_ref -n =: -w words -i cword
	else
		words=("${COMP_WORDS[@]}")
		cword=$COMP_CWORD
	fi
	local IFS=$'\n'
	# juist prints only candidates safe on a command line as they are; the
	# quoting is a second line, for a juist that did not.
	COMPREPLY=($(juist __complete "${words[@]:1:cword}" 2>/dev/null | while IFS= read -r c; do printf '%q\n' "$c"; done))
	if declare -F __ltrim_colon_completions >/dev/null; then
		__ltrim_colon_completions "${words[cword]}"
	fi
	# Nothing to offer means a file name, as approve and apply take.
	if [ ${#COMPREPLY[@]} -eq 0 ]; then
		compopt -o default 2>/dev/null
	fi
}
complete -F _juist juist
