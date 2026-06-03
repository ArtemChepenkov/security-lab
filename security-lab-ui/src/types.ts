export type FindingSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN';

export type ScanStatus = 'created' | 'running' | 'done' | 'failed' | string;

export interface ScanItem {
    id: string;
    ts: number;
    namespace: string;
    release: string;
    status: ScanStatus;
}

export type FindingType = 'vuln' | 'misconfig' | string;

export interface Finding {
    id: number;
    scanner: string;
    severity: FindingSeverity;
    target: string;
    title: string;
    cve_id: string | null;
    pkg_name: string | null;
    installed_version: string | null;
    fixed_version: string | null;
    cvss_score: number | null;
    description: string | null;
    references: string[];
    finding_type?: FindingType;
}

export interface PaginatedResponse<T> {
    items: T[];
    page: number;
    page_size: number;
    total: number;
}

export interface ScanDetailsResponse {
    scan: ScanItem;
    images: string[];
    findings: PaginatedResponse<Finding>;
}

export interface Vulnerability {
    cve_id: string;
    severity: FindingSeverity;
    cvss_score: number | null;
    title: string;
    description: string | null;
    published_at: string | null;
    modified_at: string | null;
    source: string;
    references: string[];
    updated_at: number;
}

export interface VulnerabilityDetails extends Vulnerability {
    raw: unknown;
}

export interface SbomItem {
    id: number;
    image: string;
    format: string;
    created_at: string | number | null;
}

export interface DiffResponse {
    fixed: Finding[];
    new: Finding[];
}
