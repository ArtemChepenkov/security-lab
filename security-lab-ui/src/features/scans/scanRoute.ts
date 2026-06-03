import type { ScanItem } from '../../types';

export function scanRoute(scan: Pick<ScanItem, 'id' | 'release' | 'namespace'>): string {
    if (scan.release === 'kube-bench') {
        return `/scans/cluster/${scan.id}`;
    }
    if (scan.release === 'trivy-k8s') {
        return scan.namespace === 'all-namespaces'
            ? `/scans/cluster/${scan.id}`
            : `/scans/k8s/${scan.id}`;
    }
    return `/scans/${scan.id}`;
}
