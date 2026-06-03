import {
    DiffResponse,
    PaginatedResponse,
    ScanDetailsResponse,
    ScanItem,
    SbomItem,
    Vulnerability,
    VulnerabilityDetails
} from "../types";

const API_URL = "http://130.193.53.6:8080";
const API_KEY = process.env.REACT_APP_API_KEY ?? "";

export async function startScan( release: string, chart: File):
    Promise<{
        scan_id: string;
        namespace: string;
        status: string; }> {
    const formData = new FormData();
    formData.append("release", release);
    formData.append("chart", chart);

    const response = await fetch(`${API_URL}/scan/start`, {
        method: "POST",
        headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        body: formData,
    });

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function startKubeBenchScan():
    Promise<{
        scan_id: string;
        status: string; }> {
    const response = await fetch(`${API_URL}/scan/kube-bench`, {
        method: "POST",
        headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
    });

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function startK8sScan( namespace?: string ):
    Promise<{
        scan_id: string;
        namespace: string;
        status: string; }> {
    const params = new URLSearchParams();

    if (namespace) {
        params.set("namespace", namespace);
    }

    const query = params.toString();

    const response = await fetch(
        `${API_URL}/scan/k8s${query ? `?${query}` : ""}`,
        {
            method: "POST",
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function getNamespaces(): Promise<{ items: string[] }> {
    const response = await fetch(`${API_URL}/namespaces`, {
        headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
    });

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function getScanStats(): Promise<{ total: number; by_status: Record<string, number> }> {
    const response = await fetch(`${API_URL}/scan/stats`, {
        headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
    });

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export type ScanCategory = "image" | "namespace" | "cluster" | "policy" | "all";

export async function getScans( page?: number, pageSize?: number, category?: ScanCategory ): Promise<PaginatedResponse<ScanItem>> {
    const params = new URLSearchParams();

    if (page !== undefined) {
        params.set("page", String(page));
    }

    if (pageSize !== undefined) {
        params.set("page_size", String(pageSize));
    }

    if (category) {
        params.set("category", category);
    }

    const query = params.toString();
    const response = await fetch(
        `${API_URL}/scan/list${query ? `?${query}` : ""}`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function getScanDetails(
    scanId: string,
    severity?: string[],
    scanner?: string,
    q?: string,
    page?: number,
    pageSize?: number ): Promise<ScanDetailsResponse> {
    const params = new URLSearchParams();

    if (severity?.length) {
        severity.forEach((item) => params.append("severity", item));
    }

    if (scanner) {
        params.set("scanner", scanner);
    }

    if (q) {
        params.set("q", q);
    }

    if (page !== undefined) {
        params.set("page", String(page));
    }

    if (pageSize !== undefined) {
        params.set("page_size", String(pageSize));
    }

    const query = params.toString();

    const response = await fetch(
        `${API_URL}/scan/${encodeURIComponent(scanId)}${query ? `?${query}` : ""}`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    await syncNvdForScan(scanId);

    return response.json();
}

export async function getScanSbom( scanId: string, image?: string): Promise<{ items: SbomItem[] }> {
    const params = new URLSearchParams();

    if (image) {
        params.set("image", image);
    }

    const query = params.toString();

    const response = await fetch(
        `${API_URL}/scan/${encodeURIComponent(scanId)}/sbom${query ? `?${query}` : ""}`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function downloadSbom( scanId: string, sbomId: number): Promise<Blob> {
    const response = await fetch(
        `${API_URL}/scan/${encodeURIComponent(scanId)}/sbom/${sbomId}/download`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.blob();
}

export async function getScanDiff( scan1: string, scan2: string ): Promise<DiffResponse> {
    const response = await fetch(
        `${API_URL}/scan/diff/${encodeURIComponent(scan1)}/${encodeURIComponent(scan2)}`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function deleteScan( scanId: string ): Promise<{ deleted: string }> {
    const response = await fetch(
        `${API_URL}/scan/${encodeURIComponent(scanId)}`,
        {
            method: "DELETE",
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function getVulnerabilityDetails( cveId: string ): Promise<VulnerabilityDetails> {
    const response = await fetch(
        `${API_URL}/vulnerabilities/${encodeURIComponent(cveId)}`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function syncNvdForScan(scanId: string): Promise<any> {
    const response = await fetch(
        `${API_URL}/scan/${encodeURIComponent(scanId)}/sync-nvd`,
        {
            method: "POST",
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }
}

export async function syncNvdCve( cveId: string ):
    Promise<{
        synced: string;
        source: string; }> {
    const response = await fetch(
        `${API_URL}/vulnerabilities/sync/nvd/${encodeURIComponent(cveId)}`,
        {
            method: "POST",
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function getVulnerabilities(
    severity?: string[],
    q?: string,
    page?: number,
    pageSize?: number
): Promise<PaginatedResponse<Vulnerability>> {
    const params = new URLSearchParams();

    if (severity?.length) {
        severity.forEach((item) => params.append("severity", item));
    }

    if (q) {
        params.set("q", q);
    }

    if (page !== undefined) {
        params.set("page", String(page));
    }

    if (pageSize !== undefined) {
        params.set("page_size", String(pageSize));
    }

    const query = params.toString();

    const response = await fetch(
        `${API_URL}/vulnerabilities${query ? `?${query}` : ""}`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!response.ok) {
        throw new Error(await response.text());
    }

    return response.json();
}

export async function getNvdForCve(cveId: string): Promise<VulnerabilityDetails> {
    const firstResponse = await fetch(
        `${API_URL}/vulnerabilities/${encodeURIComponent(cveId)}`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (firstResponse.ok) {
        return firstResponse.json();
    }

    await syncNvdCve(cveId);

    const secondResponse = await fetch(
        `${API_URL}/vulnerabilities/${encodeURIComponent(cveId)}`,
        {
            headers: API_KEY ? { "X-API-Key": API_KEY } : undefined,
        }
    );

    if (!secondResponse.ok) {
        throw new Error(await secondResponse.text());
    }

    return secondResponse.json();
}