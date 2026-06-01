import type { ScanItem } from '../../types';

/**
 * Куда вести при клике по скану в списке — зависит от типа скана.
 *  - kube-bench и trivy-k8s по всему кластеру → страница cluster
 *  - trivy-k8s по конкретному namespace → страница k8s
 *  - обычный скан образов (helm chart) → стандартные детали
 */
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
