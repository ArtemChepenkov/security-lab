import { useState } from 'react';
import { Link } from 'react-router-dom';
import { startK8sScan } from '../../api/scan';
import { Button } from '../../components/Button';

export function K8sScanPage() {
    const [namespace, setNamespace] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [result, setResult] = useState<{ scan_id: string; namespace: string } | null>(null);

    async function handleScan() {
        setError(null);
        setResult(null);

        try {
            setLoading(true);
            const res = await startK8sScan(namespace.trim() || undefined);
            setResult({ scan_id: res.scan_id, namespace: res.namespace });
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

            {result && (
                <div className="alert alert--success">
                    Скан запущен: <strong>{result.scan_id}</strong> ({result.namespace}).{' '}
                    <Link className="table-link" to={`/scans/${result.scan_id}`}>
                        Открыть результаты →
                    </Link>
                    <p className="muted">
                        Скан идёт в фоне. Обнови страницу деталей через минуту, статус станет «done».
                    </p>
                </div>
            )}
        </section>
    );
}
