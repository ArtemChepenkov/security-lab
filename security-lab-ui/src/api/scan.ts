import { download, request } from './client';
import type {
    DiffResponse,
    PaginatedResponse,
    ScanDetailsResponse,
    ScanItem, SbomItem,
    Vulnerability,
    VulnerabilityDetails
} from '../types';

function buildQuery(params: Record<string, string | number | string[] | undefined>) {
    const query = new URLSearchParams();

    Object.entries(params).forEach(([key, value]) => {
        if (value === undefined || value === '') return;
        if (Array.isArray(value)) value.forEach((item) => query.append(key, item));
        else query.set(key, String(value));
    });

    const result = query.toString();
    return result ? `?${result}` : '';
}

export const securityLabApi = {
    startScan(data: FormData) {
        return request<unknown>('/scan/start', { method: 'POST', body: data });
    },

    getScans(params: { page?: number; pageSize?: number; q?: string } = {}) {
        return request<PaginatedResponse<ScanItem>>(
            `/scan/list${buildQuery({ page: params.page ?? 1, page_size: params.pageSize ?? 20, q: params.q })}`,
        );
    },

    getScan(scanId: string, params: { page?: number; pageSize?: number; q?: string; severity?: string[]; scanner?: string } = {}) {
        return request<ScanDetailsResponse>(
            `/scan/${scanId}${buildQuery({
                page: params.page ?? 1,
                page_size: params.pageSize ?? 50,
                q: params.q,
                severity: params.severity,
                scanner: params.scanner,
            })}`,
        );
    },

    deleteScan(scanId: string) {
        return request<unknown>(`/scan/${scanId}`, { method: 'DELETE' });
    },

    diffScans(scan1: string, scan2: string) {
        return request<DiffResponse>(`/scan/diff/${scan1}/${scan2}`);
    },

    getSboms(scanId: string, image?: string) {
        return request<PaginatedResponse<SbomItem>>(`/scan/${scanId}/sbom${buildQuery({ image })}`);
    },

    downloadSbom(scanId: string, sbomId: number) {
        return download(`/scan/${scanId}/sbom/${sbomId}/download`, `sbom-${sbomId}.json`);
    },

    getVulnerabilities(params: { page?: number; pageSize?: number; q?: string; severity?: string[] } = {}) {
        return request<PaginatedResponse<Vulnerability>>(
            `/vulnerabilities${buildQuery({
                page: params.page ?? 1,
                page_size: params.pageSize ?? 20,
                q: params.q,
                severity: params.severity,
            })}`,
        );
    },

    getVulnerability(cve: string) {
        return request<VulnerabilityDetails>(`/vulnerabilities/${cve}`);
    },

    syncNvd(cve: string) {
        return request<unknown>(`/vulnerabilities/sync/nvd/${cve}`, { method: 'POST' });
    },
};
