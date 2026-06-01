import { useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { startK8sScan, startKubeBenchScan } from '../../api/scan';
import { Button } from '../../components/Button';
import { ScanFindingsPanel } from './ScanFindingsPanel';
import { useScanFindings } from './useScanFindings';

interface ScanResult {
    scan_id: string;
    label: string;
}

export function ClusterScanPage() {
    const { scanId } = useParams();
    const navigate = useNavigate();

    const [error, setError] = useState<string | null>(null);
    const [trivyLoading, setTrivyLoading] = useState(false);
    const [benchLoading, setBenchLoading] = useState(false);
    const [results, setResults] = useState<ScanResult[]>([]);

    const { data, loading: findingsLoading, error: findingsError } = useScanFindings(scanId ?? null);

    async function handleTrivyCluster() {
        setError(null);
        try {
            setTrivyLoading(true);
            const res = await startK8sScan(); // без namespace = весь кластер
            setResults((prev) => [{ scan_id: res.scan_id, label: 'Trivy (весь кластер)' }, ...prev]);
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
            setResults((prev) => [{ scan_id: res.scan_id, label: 'kube-bench (CIS)' }, ...prev]);
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

            {!!results.length && (
                <div className="card table-card table-card--full">
                    <div className="table-toolbar"><h2>Запущенные сканы</h2></div>
                    <div className="table-scroll">
                        <table>
                            <thead>
                            <tr><th>Scan</th><th>Тип</th><th></th></tr>
                            </thead>
                            <tbody>
                            {results.map((r) => (
                                <tr key={r.scan_id}>
                                    <td>{r.scan_id}</td>
                                    <td>{r.label}</td>
                                    <td>
                                        <button className="link-button" type="button" onClick={() => navigate(`/scans/cluster/${r.scan_id}`)}>
                                            Показать результаты
                                        </button>
                                    </td>
                                </tr>
                            ))}
                            </tbody>
                        </table>
                    </div>
                </div>
            )}

            {scanId && (
                <ScanFindingsPanel data={data} loading={findingsLoading} error={findingsError} />
            )}
        </section>
    );
}
