import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {getScans} from '../../api/scan';
import { StatusBadge } from '../../components/Badge';
import { EmptyState } from '../../components/EmptyState';
import { Pagination } from '../../components/Pagination';
import type { ScanItem } from '../../types';
import { formatDate } from '../../utils/format';
import { scanRoute } from './scanRoute';

export function ScanList() {
    const [items, setItems] = useState<ScanItem[]>([]);
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(20);
    const [total, setTotal] = useState(0);
    const [q, setQ] = useState('');
    const [debouncedQ, setDebouncedQ] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        const timeout = window.setTimeout(() => setDebouncedQ(q), 300);
        return () => window.clearTimeout(timeout);
    }, [q]);

    useEffect(() => {
        let alive = true;

        setLoading(true);
        setError(null);
        getScans(page, pageSize)
            .then((response) => {
                if (!alive) return;
                setItems(response.items || []);
                setPage(response.page || page);
                setPageSize(response.page_size || pageSize);
                setTotal(response.total || 0);
            })
            .catch((err) => alive && setError(err instanceof Error ? err.message : 'Failed to load scans'))
            .finally(() => alive && setLoading(false));

        return () => { alive = false; };
    }, [page, pageSize, debouncedQ]);

    return (
        <section className="page">
            <div className="page__header">
                <div>
                    <p className="eyebrow">Scans</p>
                    <h1>Scan history</h1>
                </div>
                <input className="search" value={q} placeholder="Search by scan, namespace, release" onChange={(event) => { setQ(event.target.value); setPage(1); }} />
            </div>

            {error && <div className="alert alert--error">{error}</div>}
            {loading && <div className="loader">Loading scans…</div>}

            {!loading && !items.length ? (
                <EmptyState title="No scans found" description="Start a new image scan or change the search filter." />
            ) : null}

            {!!items.length && (
                <div className="card table-card table-card--full">
                    <div className="table-scroll">
                        <table>
                            <thead>
                            <tr>
                                <th>Scan</th>
                                <th>Release</th>
                                <th>Namespace</th>
                                <th>Status</th>
                                <th>Created</th>
                            </tr>
                            </thead>
                            <tbody>
                            {items.map((scan) => (
                                <tr key={scan.id}>
                                    <td><Link className="table-link" to={scanRoute(scan)}>{scan.id}</Link></td>
                                    <td>{scan.release || '—'}</td>
                                    <td>{scan.namespace || '—'}</td>
                                    <td><StatusBadge status={scan.status} /></td>
                                    <td>{formatDate(scan.ts)}</td>
                                </tr>
                            ))}
                            </tbody>
                        </table>
                    </div>

                    <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
                </div>
            )}
        </section>
    );
}
