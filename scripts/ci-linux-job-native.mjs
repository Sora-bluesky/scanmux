export function nativeSuitePassed(result) {
  if (result.code !== 0 || result.signal !== null || result.launchError || result.overflow) return false;
  const output = result.stdout.toString('utf8');
  const counts = {};
  for (const field of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const matches = [...output.matchAll(new RegExp(`^# ${field} (\\d+)$`, 'gm'))];
    if (matches.length !== 1) return false;
    counts[field] = Number(matches[0][1]);
    if (!Number.isSafeInteger(counts[field])) return false;
  }
  return counts.tests > 0 && counts.pass === counts.tests && counts.fail === 0
    && counts.cancelled === 0 && counts.skipped === 0 && counts.todo === 0;
}
