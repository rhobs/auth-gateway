#!/bin/sh
set -eu

repo_root=$(CDPATH= cd "$(dirname "$0")/.." && pwd)
cd "$repo_root"

status=0

while IFS= read -r file; do
	links=$(grep -Eo '\]\([^)]*\)' "$file" || true)

	while IFS= read -r link; do
		target=${link#](}
		target=${target%)}

		case "$target" in
			\<*)
				target=${target#<}
				target=${target%%>*}
				;;
			*) target=${target%%[[:space:]]*} ;;
		esac

		case "$target" in
			''|\#*|//* ) continue ;;
			*:*)
				scheme=${target%%:*}
				case "$scheme" in
					*[!A-Za-z0-9+.-]*|'') ;;
					*) continue ;;
				esac
				;;
		esac

		target=${target%%\#*}
		target=${target%%\?*}
		[ -n "$target" ] || target=$file

		case "$target" in
			/*) resolved=.$target ;;
			*) resolved="$(dirname "$file")/$target" ;;
		esac

		if [ ! -e "$resolved" ]; then
			printf '%s: broken relative link: %s\n' "$file" "$target" >&2
			status=1
		fi
	done <<EOF
$links
EOF
done <<EOF
$(find . -type f -name '*.md' ! -path './.git/*' -print | sort)
EOF

exit "$status"
