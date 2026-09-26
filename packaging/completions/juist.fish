# fish completion for juist. The candidates come from juist itself
# ("juist __complete"), so they follow the commands and options it has.
function __juist_complete
	set -l words (commandline -opc)
	set -e words[1]
	set -l candidates (juist __complete $words (commandline -ct) 2>/dev/null)
	if test (count $candidates) -gt 0
		printf '%s\n' $candidates
	else
		# Nothing to offer means a file name, as approve and apply take.
		__fish_complete_path (commandline -ct)
	end
end

complete -c juist -f -a '(__juist_complete)'
