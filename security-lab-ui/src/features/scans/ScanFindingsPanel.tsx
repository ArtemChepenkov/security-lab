import { useMemo, useState } from 'react';
import { SeverityBadge, StatusBadge } from '../../components/Badge';
import { EmptyState } from '../../components/EmptyState';
import type { Finding, FindingSeverity, ScanDetailsResponse } from '../../types';
import { formatNumber } from '../../utils/format';

const severities: Array<FindingSeverity | 'ALL'> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const types = ['ALL', 'vuln', 'misconfig'] as const;
type TypeFilter = (typeof types)[number];

export function ScanFindingsPanel({
    data,
    loading,
    error,
}: {
    data: ScanDetailsResponse | null;
    loading: boolean;
    error: string | null;
}) {
    const [severity, setSeverity] = useState<FindingSeverity | 'ALL'>('ALL');
    const [type, setType] = useState<TypeFilter>('ALL');
    const [q, setQ] = useState('');

    const allFindings = data?.findings.items ?? [];

    const filtered = useMemo(() => {
        const needle = q.trim().toLowerCase();
        return allFindings.filter((f) => {
            if (severity !== 'ALL' && f.severity !== severity) return false;
            if (type !== 'ALL' && (f.finding_type ?? 'vuln') !== type) return false;
            if (needle) {
                const hay = `${f.title} ${f.target} ${f.cve_id ?? ''}`.toLowerCase();
                if (!hay.includes(needle)) return false;
            }
            return true;
        });
    }, [allFindings, severity, type, q]);

    const counts = useMemo(() => {
        const c = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0 } as Record<string, number>;
        allFindings.forEach((f) => { c[f.severity] = (c[f.severity] ?? 0) + 1; });
        return c;
    }, [allFindings]);

    const status = data?.scan.status?.toLowerCase();
    const isRunning = status === 'running' || status === 'created';

    return (
        <>
            {error && <div className="alert alert--error">{error}</div>}

            {data && (
                <>
                    <div className="summary-grid">
                        <article className="metric-card">
                            <span>Status</span>
                            <strong><StatusBadge status={data.scan.status} /></strong>
                        </article>
                        <article className="metric-card">
                            <span>Findings</span>
                            <strong>{allFindings.length}</strong>
                        </article>
                        <article className="metric-card">
                            <span>Critical / High</span>
                            <strong>{counts.CRITICAL} / {counts.HIGH}</strong>
                        </article>
                    </div>

                    {isRunning && (
                        <div className="alert alert--success">
                            Скан выполняется… результаты обновятся автоматически.
                        </div>
                    )}

                    <div className="card table-card table-card--full">
                        <div className="table-toolbar">
                            <h2>Findings</h2>
                            <div className="filters">
                                <select value={severity} onChange={(e) => setSeverity(e.target.value as FindingSeverity | 'ALL')}>
                                    {severities.map((item) => <option key={item} value={item}>{item}</option>)}
                                </select>
                                <select value={type} onChange={(e) => setType(e.target.value as TypeFilter)}>
                                    {types.map((item) => (
                                        <option key={item} value={item}>
                                            {item === 'ALL' ? 'All types' : item}
                                        </option>
                                    ))}
                                </select>
                                <input className="search" value={q} placeholder="Search findings" onChange={(e) => setQ(e.target.value)} />
                            </div>
                        </div>

                        {!filtered.length ? (
                            <EmptyState
                                title="No findings"
                                description={isRunning ? 'Скан ещё идёт.' : 'Ничего не найдено по текущим фильтрам.'}
                            />
                        ) : (
                            <div className="table-scroll">
                                <table>
                                    <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Type</th>
                                        <th>CVE</th>
                                        <th>Target</th>
                                        <th>CVSS</th>
                                        <th>Title</th>
                                    </tr>
                                    </thead>
                                    <tbody>
                                    {filtered.map((finding: Finding) => (
                                        <tr key={finding.id}>
                                            <td><SeverityBadge severity={finding.severity} /></td>
                                            <td>{finding.finding_type ?? 'vuln'}</td>
                                            <td>{finding.cve_id || '—'}</td>
                                            <td>{finding.target || '—'}</td>
                                            <td>{formatNumber(finding.cvss_score)}</td>
                                            <td>{finding.title}</td>
                                        </tr>
                                    ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </>
            )}

            {loading && !data && <div className="loader">Loading…</div>}
        </>
    );
}
