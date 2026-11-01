import { SafeError } from '../safety.ts';
import { isDay, isTimestamp, toCveId, type CveId } from './syntax.ts';

export interface KevEntry {
  readonly cveID: CveId; readonly vendorProject: string; readonly product: string; readonly vulnerabilityName: string;
  readonly dateAdded: string; readonly dueDate: string; readonly knownRansomwareCampaignUse: string | null;
}
export interface KevCatalog { readonly catalogVersion: string; readonly dateReleased: string; readonly entries: ReadonlyMap<CveId, KevEntry> }
function drift(condition: unknown): asserts condition { if (!condition) throw new SafeError('intel_schema_drift'); }
const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const text = (value: unknown): string => { drift(typeof value === 'string' && value.length > 0 && value.length <= 4096); return value as string; };
const day = (value: unknown): string => { drift(isDay(value)); return value; };

export function parseKev(bytes: Buffer): KevCatalog {
  let top: unknown;
  try { top = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { throw new SafeError('intel_schema_drift'); }
  drift(isObject(top) && Array.isArray(top.vulnerabilities) && Number.isSafeInteger(top.count) && top.count === top.vulnerabilities.length);
  drift(typeof top.catalogVersion === 'string' && /^[0-9A-Za-z._-]{1,64}$/.test(top.catalogVersion));
  drift(isTimestamp(top.dateReleased));
  const entries = new Map<CveId, KevEntry>(), known = new Map<CveId, string>();
  for (const item of top.vulnerabilities as unknown[]) {
    drift(isObject(item));
    const cveID = toCveId(item.cveID);
    drift(cveID !== null && cveID === item.cveID);
    const shortDescription = text(item.shortDescription), requiredAction = text(item.requiredAction);
    drift(item.knownRansomwareCampaignUse === undefined || typeof item.knownRansomwareCampaignUse === 'string');
    const entry: KevEntry = { cveID, vendorProject: text(item.vendorProject), product: text(item.product), vulnerabilityName: text(item.vulnerabilityName),
      dateAdded: day(item.dateAdded), dueDate: day(item.dueDate), knownRansomwareCampaignUse: (item.knownRansomwareCampaignUse as string | undefined) ?? null };
    const full = JSON.stringify({ ...entry, shortDescription, requiredAction });
    drift(!known.has(cveID) || known.get(cveID) === full);
    known.set(cveID, full); entries.set(cveID, entry);
  }
  return { catalogVersion: top.catalogVersion, dateReleased: top.dateReleased, entries };
}
