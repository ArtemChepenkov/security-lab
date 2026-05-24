
export type ScanRow = [
    id: string,
    ts: number,
    namespase: string,
    release: string,
    status: string
];

export type ImageRow = [
    image: string
];

export type FindingSeverity =
    | "LOW"
    | "MEDIUM"
    | "HIGH"
    | "CRITICAL";

export type FindingRow = [
    scanner: string,
    severity: FindingSeverity,
    image: string,
    description: string
];

export interface ScanInfo {
    scan: ScanRow;
    images: ImageRow[];
    findings: FindingRow[];
}