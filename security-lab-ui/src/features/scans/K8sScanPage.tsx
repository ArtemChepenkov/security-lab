import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { getNamespaces, startK8sScan } from '../../api/scan';
import { Button } from '../../components/Button';
import type { ScanItem } from '../../types';
import { LaunchedScansTable } from './LaunchedScansTable';
import { ScanFindingsPanel } from './ScanFindingsPanel';
import { useScanFindings } from './useScanFindings';
import { useScansOfType } from './useScansOfType';

// trivy-k8s по конкретному namespace (не весь кластер)
const isNamespaceScan = (s: ScanItem) =>
    s.release === 'trivy-k8s' && s.namespace !== 'all-namespaces';

export function K8sScanPage() {
    const { scanId } = useParams();
    const navigate = useNavigate();

    const [namespace, setNamespace] = useState('');
    const [namespaceOptions, setNamespaceOptions] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const { data, loading: findingsLoading, error: findingsError } = useScanFindings(scanId ?? null);
    const { scans, reload } = useScansOfType(isNamespaceScan);

    useEffect(() => {
        getNamespaces()
            .then((res) => setNamespaceOptions(res.items || []))
            .catch(() => setNamespaceOptions([]));
    }, []);

    async function handleScan() {
        setError(null);
        try {
            setLoading(true);
            const res = await startK8sScan(namespace.trim() || undefined);
            reload();
            navigate(`/scans/k8s/${res.scan_id}`);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to start k8s scan');
        } finally {
            setLoading(false);
        }
    }

    return (
        <section className="page">
            <div className="page__header">
                <div>
                    <p className="eyebrow">Kubernetes</p>
                    <h1>Trivy k8s scan</h1>
                    <p className="muted">
                        Сканирует ресурсы namespace через Trivy: образы (CVE) и мисконфиги
                        (privileged-контейнеры, RBAC, отсутствие лимитов и т.д.).
                    </p>
                </div>
            </div>

            {error && <div className="alert alert--error">{error}</div>}

            <div className="card nvd-section">
                <h2>Запустить скан namespace</h2>
                <div className="form">
                    <label>
                        Namespace
                        <input
                            list="namespace-options"
                            value={namespace}
                            placeholder="default (пусто = весь кластер)"
                            onChange={(event) => setNamespace(event.target.value)}
                        />
                        <datalist id="namespace-options">
                            {namespaceOptions.map((ns) => <option key={ns} value={ns} />)}
                        </datalist>
                    </label>
                    <Button onClick={handleScan} disabled={loading}>
                        {loading ? 'Запуск…' : 'Сканировать namespace'}
                    </Button>
                </div>
            </div>

            <LaunchedScansTable
                scans={scans}
                activeId={scanId}
                onSelect={(id) => navigate(`/scans/k8s/${id}`)}
            />

            {scanId && (
                <ScanFindingsPanel data={data} loading={findingsLoading} error={findingsError} />
            )}
        </section>
    );
}
