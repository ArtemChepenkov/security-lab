import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { startK8sScan } from '../../api/scan';
import { Button } from '../../components/Button';
import { ScanFindingsPanel } from './ScanFindingsPanel';
import { useScanFindings } from './useScanFindings';

export function K8sScanPage() {
    const { scanId } = useParams();
    const navigate = useNavigate();

    const [namespace, setNamespace] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const { data, loading: findingsLoading, error: findingsError } = useScanFindings(scanId ?? null);

    // Если зашли на /scans/k8s/:scanId — подставим namespace из загруженного скана.
    useEffect(() => {
        if (data?.scan?.namespace && data.scan.namespace !== 'all-namespaces') {
            setNamespace(data.scan.namespace);
        }
    }, [data?.scan?.namespace]);

    async function handleScan() {
        setError(null);
        try {
            setLoading(true);
            const res = await startK8sScan(namespace.trim() || undefined);
            // Переходим на URL с id — хук подхватит и начнёт опрашивать.
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
                            value={namespace}
                            placeholder="default (пусто = весь кластер)"
                            onChange={(event) => setNamespace(event.target.value)}
                        />
                    </label>
                    <Button onClick={handleScan} disabled={loading}>
                        {loading ? 'Запуск…' : 'Сканировать namespace'}
                    </Button>
                </div>
            </div>

            {scanId && (
                <ScanFindingsPanel data={data} loading={findingsLoading} error={findingsError} />
            )}
        </section>
    );
}
