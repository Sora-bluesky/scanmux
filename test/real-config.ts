export const realConfigPath = process.env.SCANMUX_REAL_CONFIG || undefined;
export const realConfigSkip = realConfigPath ? false
  : 'requires SCANMUX_REAL_CONFIG, the absolute path of a ScanMux config naming real git, gitleaks and osv; not counted as PASS';
