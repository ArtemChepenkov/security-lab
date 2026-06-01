import { useEffect, useState } from 'react';
import {getVulnerabilities, syncNvdCve} from '../../api/scan';
import { SeverityBadge } from '../../components/Badge';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import { Pagination } from '../../components/Pagination';
import type { FindingSeverity, Vulnerability } from '../../types';
import { formatNumber } from '../../utils/format';

const severities: Array<FindingSeverity | 'ALL'> = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

export function VulnerabilitiesPage() {
  const [items, setItems] = useState<Vulnerability[]>([]);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState('');
  const [severity, setSeverity] = useState<FindingSeverity | 'ALL'>('ALL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);

    getVulnerabilities(
        severity === 'ALL' ? undefined : [severity],
        q,
        page,
        pageSize
    )
        .then((response) => {
          if (!alive) return;
          setItems(response.items || []);
          setPage(response.page || page);
          setPageSize(response.page_size || pageSize);
          setTotal(response.total || 0);
        })
        .catch((err: unknown) => {
          if (!alive) return;
          setError(err instanceof Error ? err.message : 'Failed to load vulnerabilities');
        })
        .finally(() => alive && setLoading(false));

    return () => { alive = false; };
  }, [page, pageSize, q, severity]);

  async function sync(cve: string) {
    try {
      await syncNvdCve(cve);
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to sync ${cve}`);
    }
  }

  return (
    <section className="page">
      <div className="page__header">
        <div>
          <p className="eyebrow">Database</p>
          <h1>Vulnerabilities</h1>
        </div>
        <div className="filters">
          <select value={severity} onChange={(event) => { setSeverity(event.target.value as FindingSeverity | 'ALL'); setPage(1); }}>
            {severities.map((item) => <option key={item} value={item}>{item}</option>)}
          </select>
          <input className="search" value={q} placeholder="Search CVE or title" onChange={(event) => { setQ(event.target.value); setPage(1); }} />
        </div>
      </div>

      {error && <div className="alert alert--error">{error}</div>}
      {loading && <div className="loader">Loading vulnerabilities…</div>}
      {!loading && !items.length ? <EmptyState title="No vulnerabilities" description="Try another filter or search query." /> : null}

      {!!items.length && (
        <div className="card table-card">
          <table>
            <thead>
              <tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Title</th><th>Source</th><th>Action</th></tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.cve_id}>
                  <td>{item.cve_id}</td>
                  <td><SeverityBadge severity={item.severity} /></td>
                  <td>{formatNumber(item.cvss_score)}</td>
                  <td>{item.title}</td>
                  <td>{item.source}</td>
                  <td><Button variant="secondary" onClick={() => sync(item.cve_id)}>Sync NVD</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination page={page} pageSize={pageSize} total={total} onPageChange={setPage} onPageSizeChange={(size) => { setPageSize(size); setPage(1); }} />
        </div>
      )}
    </section>
  );
}
