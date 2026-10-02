#!/system/bin/sh
dir=/data/local/tmp/dfroot-shell
umask 007

fail() {
    rc=$?
    setprop debug.dfroot.error "$1:$rc"
    exit "$rc"
}

setprop debug.dfroot.error ''
mkdir -p "$dir" || fail mkdir
: > "$dir/in" || fail create_in
: > "$dir/out" || fail create_out
chmod 0660 "$dir/in" "$dir/out" || fail mode_channels
id > "$dir/status" || fail write_status
chmod 0644 "$dir/status" || fail mode_status
setprop debug.dfroot.ready 1 || fail ready_property

while true; do
    if [ ! -s "$dir/in" ]; then
        sleep 0.2
        continue
    fi
    IFS= read -r command < "$dir/in"
    : > "$dir/in"
    if [ "$command" = ':exit' ]; then
        echo 'root command channel stopped' > "$dir/out"
        break
    fi
    eval "$command" > "$dir/out" 2>&1
    printf '\n__DFROOT_DONE__:%d\n' "$?" >> "$dir/out"
done
