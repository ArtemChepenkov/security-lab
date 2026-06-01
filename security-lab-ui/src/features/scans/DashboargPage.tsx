import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { getScans } from '../../api/scan';
import { StatusBadge } from '../../components/Badge';
import type { ScanItem } from '../../types';
import { formatDate } from '../../utils/format';

export function DashboardPage() {
    const [scans, setScans] = useState<ScanItem[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        let alive = true;
        getScans(1, 5)
            .then((response) => {
                if (!alive) return;
                setScans(response.items || []);
                setTotal(response.total || 0);
            })
            .finally(() => alive && setLoading(false));
        return () => { alive = false; };
    }, []);

    const stats = useMemo(() => {
        const running = scans.filter((scan) => scan.status.toLowerCase() === 'running').length;
        const failed = scans.filter((scan) => scan.status.toLowerCase() === 'failed').length;
        let done = scans.filter((scan) => scan.status.toLowerCase() === 'done').length;
        done += scans.filter((scan) => scan.status.toLowerCase() === 'created').length;
        return { total, running, failed, done };
    }, [scans, total]);

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
                                    <td><Link className="table-link" to={`/scans/${scan.id}`}>{scan.id}</Link></td>
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
