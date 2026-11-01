export type CveId = string & { readonly __brand: 'CveId' };
export function toCveId(value: unknown): CveId | null {
  if (typeof value !== 'string' || value.length > 64) return null;
  const id = value.trim().toUpperCase();
  return /^CVE-\d{4}-\d{4,}$/.test(id) ? id as CveId : null;
}
const rfc3339 = /^(\d{4}-\d\d-\d\d)T(\d\d):(\d\d)(?::(\d\d)(?:\.\d{1,9})?)?(?:Z|[+-](\d\d):(\d\d))$/;
export function isDay(value: unknown): value is string {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\d$/.test(value)) return false;
  const time = Date.parse(`${value}T00:00:00Z`);
  return Number.isFinite(time) && new Date(time).toISOString().slice(0, 10) === value;
}
export function isTimestamp(value: unknown): value is string {
  const parts = typeof value === 'string' ? rfc3339.exec(value) : null;
  return parts !== null && isDay(parts[1]) && [parts[2], parts[5]].every(hours => Number(hours ?? 0) <= 23)
    && [parts[3], parts[4], parts[6]].every(minutes => Number(minutes ?? 0) <= 59) && Number.isFinite(Date.parse(parts[0]));
}
