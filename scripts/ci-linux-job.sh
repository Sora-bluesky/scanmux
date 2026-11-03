#!/usr/bin/env bash
set -euo pipefail
repository=$(cd -- "$(dirname -- "$0")/.." && pwd)
work=${SCANMUX_LINUX_JOB_WORK:-${RUNNER_TEMP:?Set SCANMUX_LINUX_JOB_WORK for local runs}/scanmux-linux-job}
if [[ $work != /* || $work == / || $work == *[!a-zA-Z0-9/_-]* ]]; then
  printf '%s\n' 'The work directory must be a dedicated absolute Linux path without mount-option delimiters.' >&2
  exit 1
fi
mkdir -p -- "$work"
mkdir -- "$work/evidence"
id=$(node --input-type=module -e "import { randomUUID } from 'node:crypto'; console.log(randomUUID().replaceAll('-', ''));")
run="$work/run-$id"
mkdir -- "$run"
name="scanmux-ci-linux-job-$id"
created=false
finish() {
  status=$?
  trap - EXIT
  if "$created"; then
    docker cp "$name:$run/out/." "$work/evidence/" || status=1
    label=$(docker inspect --format '{{index .Config.Labels "scanmux.ci-linux-job"}}' "$name") || label=''
    if [[ $label == "$id" ]]; then
      docker rm --force "$name" >/dev/null || status=1
    else
      printf '%s\n' 'Outer container ownership could not be verified.' >&2
      status=1
    fi
  fi
  printf '{"exitCode":%d}\n' "$status" > "$work/evidence/launcher-exit.json"
  exit "$status"
}
trap finish EXIT
image=$(node --input-type=module - "$repository/.github/scanmux/linux-job-pins.json" <<'NODE'
import { readFile } from 'node:fs/promises';
const pins = JSON.parse(await readFile(process.argv[2], 'utf8'));
if (pins.schema !== 'scanmux.ci-linux-job-pins/v1'
    || !/^node:24\.22\.1-bookworm@sha256:[a-f0-9]{64}$/.test(pins.image)) {
  throw Error('Fill the reviewed Linux amd64 image digest in .github/scanmux/linux-job-pins.json');
}
console.log(pins.image);
NODE
)
docker pull --platform linux/amd64 "$image"
image_id=$(docker image inspect --format '{{.Id}}' "$image")
[[ $image_id =~ ^sha256:[a-f0-9]{64}$ ]]
# Use working-tree bytes so local runs include uncommitted changes.
tar --exclude=node_modules -cf "$run/source.tar" -C "$repository" -- \
  LICENSE NOTICE README.md README.ja.md bin src internal scripts test package.json package-lock.json \n  .github/scanmux/linux-job-pins.json
docker create --pull=never --name "$name" --label "scanmux.ci-linux-job=$id" \
  --mount type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock \
  --mount "type=bind,source=$work,target=$work" \
  --entrypoint /bin/bash "$image_id" /tmp/scanmux-linux-job-bootstrap.sh "$run" "$image_id" >/dev/null
created=true
docker cp "$run/source.tar" "$name:/tmp/scanmux-linux-job-source.tar"
docker cp "$repository/scripts/ci-linux-job-bootstrap.sh" "$name:/tmp/scanmux-linux-job-bootstrap.sh"
docker start --attach "$name"
state=$(docker inspect --format '{{.State.Running}} {{.State.ExitCode}}' "$name")
read -r running exit_code <<< "$state"
[[ $running == false && $exit_code =~ ^[0-9]+$ ]]
exit "$exit_code"
