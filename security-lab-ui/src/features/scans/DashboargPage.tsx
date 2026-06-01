import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { getScans, getScanStats } from '../../api/scan';
import { StatusBadge } from '../../components/Badge';
import type { ScanItem } from '../../types';
import { formatDate } from '../../utils/format';
import { scanRoute } from './scanRoute';

export function DashboardPage() {
    const [scans, setScans] = useState<ScanItem[]>([]);
    const [statusCounts, setStatusCounts] = useState<{ total: number; by_status: Record<string, number> }>({
        total: 0,
        by_status: {},
    });
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let alive = true;

        // Последние 5 сканов — для таблицы; статистика — по всем сканам.
        Promise.all([getScans(1, 5), getScanStats()])
            .then(([scansRes, statsRes]) => {
                if (!alive) return;
                setScans(scansRes.items || []);
                setStatusCounts(statsRes);
            })
            .finally(() => alive && setLoading(false));

        return () => { alive = false; };
    }, []);

    const stats = useMemo(() => {
        const by = statusCounts.by_status || {};
        return {
            total: statusCounts.total,
            running: by.running ?? 0,
            failed: by.failed ?? 0,
            done: (by.done ?? 0) + (by.created ?? 0),
        };
    }, [statusCounts]);

    return (
        <section className="page">
            <div className="page__header">
                <div>
                    <p className="eyebrow">Overview</p>
                    <h1>Security dashboard</h1>
                    <p className="muted">Recent image scans and vulnerability intelligence.</p>
                </div>
            </div>

            <div className="summary-grid">
                <article className="metric-card"><span>Total scans</span><strong>{stats.total}</strong></article>
                <article className="metric-card"><span>Done</span><strong>{stats.done}</strong></article>
                <article className="metric-card"><span>Running</span><strong>{stats.running}</strong></article>
                <article className="metric-card"><span>Failed</span><strong>{stats.failed}</strong></article>
            </div>

            <div className="card table-card table-card--compact">
                <div className="table-toolbar"><h2>Latest scans</h2><Link className="table-link" to="/scans">View all</Link></div>
                {loading ? <div className="loader">Loading dashboard…</div> : (
                    <div className="table-scroll">
                        <table>
                            <thead><tr><th>Scan</th><th>Release</th><th>Status</th><th>Created</th></tr></thead>
                            <tbody>
                            {scans.map((scan) => (
                                <tr key={scan.id}>
                                    <td><Link className="table-link" to={scanRoute(scan)}>{scan.id}</Link></td>
                                    <td>{scan.release || '—'}</td>
                                    <td><StatusBadge status={scan.status} /></td>
                                    <td>{formatDate(scan.ts)}</td>
                                </tr>
                            ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </section>
    );
}
