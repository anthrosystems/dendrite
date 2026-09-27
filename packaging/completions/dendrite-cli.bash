# Bash completion for dendrite-cli.
#
# This script does not hardcode a copy of dendrite-cli's command tree.
# Instead it asks the binary itself, via `dendrite-cli --list-commands`,
# for the flat list of every recognised token path (see
# `Command::command_paths()` in crates/dendrite-cli/src/lib.rs). This means
# the completion script never drifts out of sync with the parser as
# commands are added or removed — there is nothing here to update when
# that list changes.
#
# Deliberately does not depend on the `bash-completion` package's
# `_init_completion` helper, so it keeps working on minimal systems that
# don't have it installed.
#
# Install by sourcing this file, or dropping it in
# /usr/share/bash-completion/completions/dendrite-cli (packaged that way
# by this project's .deb — see crates/dendrited/Cargo.toml).

_dendrite_cli() {
    local cur words_typed candidates paths_output

    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"

    # Top-level flags that aren't part of command_paths() (it only lists
    # literal command-token paths, not option aliases).
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=($(compgen -W "-h --help -V --version" -- "${cur}"))
    fi

    # Everything already typed before the word being completed, e.g. for
    # `dendrite-cli guard rec<TAB>` this is "guard" and cur is "rec".
    words_typed="${COMP_WORDS[*]:1:COMP_CWORD-1}"

    paths_output="$(dendrite-cli --list-commands 2>/dev/null)" || return 0

    if [[ -z "${words_typed}" ]]; then
        # Completing the first token: offer every distinct first word.
        candidates="$(awk '{print $1}' <<<"${paths_output}" | sort -u)"
    else
        # Offer the next token after the words already typed, for lines
        # that start with exactly those words.
        candidates="$(awk -v prefix="${words_typed}" '
            {
                line = $0
                n = split(prefix, pwords, " ")
                match_ok = 1
                for (i = 1; i <= n; i++) {
                    if ($i != pwords[i]) { match_ok = 0; break }
                }
                if (match_ok && NF > n) {
                    print $(n + 1)
                }
            }
        ' <<<"${paths_output}" | sort -u)"
    fi

    COMPREPLY+=($(compgen -W "${candidates}" -- "${cur}"))
    return 0
}

complete -F _dendrite_cli dendrite-cli
