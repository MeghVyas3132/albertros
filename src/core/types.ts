export type Severity = 'danger' | 'review' | 'info' | 'good';
export type Verdict = 'danger' | 'review' | 'safe' | 'unknown';

export interface Finding {
  code: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence?: string[];
  link?: string;
}

export interface DepInput {
  name: string;
  spec: string;
  direct: boolean;
  dev?: boolean;
}

export interface PackageMeta {
  publishedAt?: string;
  publisher?: string;
  weeklyDownloads?: number | null;
  description?: string;
  repository?: string;
  license?: string;
  unpackedSize?: number;
  hasInstallScript?: boolean;
  provenance?: boolean;
  signature?: 'valid' | 'invalid' | 'missing' | 'unknown-key';
  integrity?: 'verified' | 'mismatch';
  source?: { status: string; repo?: string; commit?: string; compared: number; matched: number; modified: number; notInGit: number };
}

export interface PackageReport {
  name: string;
  spec: string;
  version?: string;
  direct: boolean;
  dev: boolean;
  verdict: Verdict;
  findings: Finding[];
  meta: PackageMeta;
  scanned: boolean;
  error?: string;
}

export interface ProjectReport {
  source: string;
  packages: PackageReport[];
  score: number;
  counts: Record<Verdict, number>;
  startedAt: string;
  finishedAt: string;
  skipped: number;
}

export interface Progress {
  stage: string;
  done: number;
  total: number;
}

export interface AnalyzeOptions {
  deep?: boolean;
  maxPackages?: number;
  now?: number;
  onProgress?: (p: Progress) => void;
}
