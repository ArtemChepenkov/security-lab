import { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import {deleteScan, getScanDetails} from '../../api/scan';
import { SeverityBadge, StatusBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import { Pagination } from '../../components/Pagination';
import type { Finding, FindingSeverity, ScanDetailsResponse, VulnerabilityDetails} from '../../types';
import { formatDate, formatNumber } from '../../utils/format';
import {VulnerabilityDetailsModal} from "./VulnerabilityDetailsModal";

const severities: Array<FindingSeverity | 'ALL'> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
const scanners = ['ALL', 'trivy', 'grype'] as const;
type ScannerFilter = (typeof scanners)[number];

export function ScanDetailsPage() {
    const { scanId = '' } = useParams();
    const navigate = useNavigate();
    const [data, setData] = useState<ScanDetailsResponse | null>(null);
    const [severity, setSeverity] = useState<FindingSeverity | 'ALL'>('ALL');
    const [scanner, setScanner] = useState<ScannerFilter>('ALL');
    const [q, setQ] = useState('');
    const [page, setPage] = useState(1);
    const [pageSize, setPageSize] = useState(50);

    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

    useEffect(() => {
        let alive = true;
        setLoading(true);
        setError(null);

        getScanDetails(scanId, severity === 'ALL' ? undefined : [severity], scanner === 'ALL' ? undefined : scanner, q, page, pageSize )
            .then((response) => alive && setData(response))
            .catch((err) => alive && setError(err instanceof Error ? err.message : 'Failed to load scan'))
            .finally(() => alive && setLoading(false));

        return () => { alive = false; };
    }, [scanId, page, pageSize, q, severity, scanner]);

    async function handleDelete() {
        const confirmed = window.confirm('Delete this scan?');
        if (!confirmed) return;

        try {
            await deleteScan(scanId);
            navigate('/scans');
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to delete scan');
        }
    }

    function handleOpenNvd(finding: Finding) {
        setSelectedFinding(finding);
    }

    const findings = data?.findings.items ?? [];
    const total = data?.findings.total ?? 0;

    return (
        <section className="page">
            <div className="page__header">
                <div>
                    <Link className="back-link" to="/scans">← Back to scans</Link>
                    <h1>{data?.scan.release || scanId}</h1>
                    {data && <p className="muted">Namespace {data.scan.namespace || '—'} · Created {formatDate(data.scan.ts)}</p>}
                </div>
                <div className="header-actions">
                    <Link className="btn btn--secondary" to={`/scans/${scanId}/sbom`}>SBOMs</Link>
                    <Button variant="danger" onClick={handleDelete}>Delete</Button>
                </div>
            </div>

            {error && <div className="alert alert--error">{error}</div>}
            {loading && <div className="loader">Loading scan…</div>}

            {data && (
                <>
                    <div className="summary-grid">
                        <article className="metric-card">
                            <span>Status</span>
                            <strong>
                                <StatusBadge status={data.scan.status} />
                            </strong>
                        </article>
                        <article className="metric-card">
                            <span>Images</span>
                            <strong>
                                {data.images.length}
                                <div className="chip-list">
                                    {data.images.map((image) => <span className="chip" key={image}>{image}</span>)}
                                </div>
                            </strong>
                        </article>
                        <article className="metric-card">
                            <span>Findings</span>
                            <strong>{total}</strong>
                        </article>
                    </div>

                    <div className="card table-card table-card--half">
                        <div className="table-toolbar">
                            <h2>Findings</h2>
                            <div className="filters">
                                <select value={severity} onChange={(event) => { setSeverity(event.target.value as FindingSeverity | 'ALL'); setPage(1); }}>
                                    {severities.map((item) => <option key={item} value={item}>{item}</option>)}
                                </select>
                                <select value={scanner} onChange={(event) => { setScanner(event.target.value as ScannerFilter); setPage(1); }}>
                                    {scanners.map((item) => <option key={item} value={item}>{item === 'ALL' ? 'All scanners' : item}</option>)}
                                </select>
                                <input className="search" value={q} placeholder="Search findings" onChange={(event) => { setQ(event.target.value); setPage(1); }} />
                            </div>
                        </div>

                        {!findings.length ? (
                            <EmptyState title="No findings" description="Try another severity or search filter." />
                        ) : (
                                <div className="table-scroll">
                                    <table>
                                        <thead>
                                        <tr>
                                            <th>Severity</th>
                                            <th>CVE</th>
                                            <th>Package</th>
                                            <th>Installed</th>
                                            <th>Fixed</th>
                                            <th>CVSS</th>
                                            <th>Scanner</th>
                                            <th>Title</th>
                                        </tr>
                                        </thead>
                                        <tbody>
                                        {findings.map((finding: Finding) => (
                                            <tr key={finding.id}>
                                                <td><SeverityBadge severity={finding.severity} /></td>
                                                <td>
                                                    {finding.cve_id ? (
                                                        <button
                                                            className="link-button"
                                                            type="button"
                                                            onClick={() => handleOpenNvd(finding)}
                                                        >
                                                            {finding.cve_id}
                                                        </button>
                                                    ) : (
                                                        '—'
                                                    )}
                                                </td>                                                <td>{finding.pkg_name || '—'}</td>
                                                <td>{finding.installed_version || '—'}</td>
                                                <td>{finding.fixed_version || '—'}</td>
                                                <td>{formatNumber(finding.cvss_score)}</td>
                                                <td>{finding.scanner}</td>
                                                <td>{finding.title}</td>
                                            </tr>
                                        ))}
                                        </tbody>
                                    </table>
                                </div>
                        )}

                        <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
                    </div>
                </>
            )}

            {selectedFinding && (
                <VulnerabilityDetailsModal
                    finding={selectedFinding}
                    onClose={() => setSelectedFinding(null)}
                    onError={setError}
                />
            )}
        </section>
    );
}
