import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { startK8sScan, startKubeBenchScan } from '../../api/scan';
import { Button } from '../../components/Button';
import type { ScanItem } from '../../types';
import { LaunchedScansTable } from './LaunchedScansTable';
import { ScanFindingsPanel } from './ScanFindingsPanel';
import { useScanFindings } from './useScanFindings';
import { useScansOfType } from './useScansOfType';

// kube-bench и trivy-k8s по всему кластеру
const isClusterScan = (s: ScanItem) =>
    s.release === 'kube-bench' || (s.release === 'trivy-k8s' && s.namespace === 'all-namespaces');

export function ClusterScanPage() {
    const { scanId } = useParams();
    const navigate = useNavigate();

    const [error, setError] = useState<string | null>(null);
    const [trivyLoading, setTrivyLoading] = useState(false);
    const [benchLoading, setBenchLoading] = useState(false);

    const { data, loading: findingsLoading, error: findingsError } = useScanFindings(scanId ?? null);
    const { scans, reload } = useScansOfType(isClusterScan);

    async function handleTrivyCluster() {
        setError(null);
        try {
            setTrivyLoading(true);
            const res = await startK8sScan(); // без namespace = весь кластер
            reload();
            navigate(`/scans/cluster/${res.scan_id}`);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to start trivy cluster scan');
        } finally {
            setTrivyLoading(false);
        }
    }

    async function handleKubeBench() {
        setError(null);
        try {
            setBenchLoading(true);
            const res = await startKubeBenchScan();
            reload();
            navigate(`/scans/cluster/${res.scan_id}`);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to start kube-bench scan');
        } finally {
            setBenchLoading(false);
        }
    }

    return (
        <section className="page">
            <div className="page__header">
                <div>
                    <p className="eyebrow">Kubernetes</p>
                    <h1>Скан всего кластера</h1>
                    <p className="muted">
                        Полная проверка кластера: уязвимости и мисконфиги всех ресурсов через Trivy,
                        плюс соответствие CIS-бенчмарку через kube-bench.
                    </p>
                </div>
            </div>

            {error && <div className="alert alert--error">{error}</div>}

            <div className="summary-grid">
                <article className="metric-card">
                    <span>Trivy — весь кластер</span>
                    <p className="muted">CVE в образах + мисконфиги по всем namespace.</p>
                    <Button onClick={handleTrivyCluster} disabled={trivyLoading}>
                        {trivyLoading ? 'Запуск…' : 'Запустить Trivy'}
                    </Button>
                </article>

                <article className="metric-card">
                    <span>kube-bench — CIS</span>
                    <p className="muted">Проверка настроек кластера на соответствие CIS Kubernetes Benchmark.</p>
                    <Button onClick={handleKubeBench} disabled={benchLoading}>
                        {benchLoading ? 'Запуск…' : 'Запустить kube-bench'}
                    </Button>
                </article>
            </div>

            <LaunchedScansTable
                scans={scans}
                activeId={scanId}
                onSelect={(id) => navigate(`/scans/cluster/${id}`)}
            />

            {scanId && (
                <ScanFindingsPanel data={data} loading={findingsLoading} error={findingsError} />
            )}
        </section>
    );
}
