import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { getScanSbom, downloadSbom } from '../../api/scan';
import { Button } from '../../components/Button';
import { EmptyState } from '../../components/EmptyState';
import type { SbomItem } from '../../types';
import { formatDate } from '../../utils/format';

export function SbomPage() {
    const { scanId = '' } = useParams();
    const [items, setItems] = useState<SbomItem[]>([]);
    const [image, setImage] = useState('');
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        let alive = true;
        setLoading(true);
        setError(null);

        getScanSbom(scanId, image || undefined)
            .then((response) => alive && setItems(response.items || []))
            .catch((err) => alive && setError(err instanceof Error ? err.message : 'Failed to load SBOMs'))
            .finally(() => alive && setLoading(false));

        return () => { alive = false; };
    }, [scanId, image]);

    return (
        <section className="page">
            <div className="page__header">
                <div>
                    <Link className="back-link" to={`/scans/${scanId}`}>← Back to scan</Link>
                    <h1>SBOMs</h1>
                    <p className="muted">Scan {scanId}</p>
                </div>
                <input className="search" value={image} placeholder="Filter by image" onChange={(event) => setImage(event.target.value)} />
            </div>

            {error && <div className="alert alert--error">{error}</div>}
            {loading && <div className="loader">Loading SBOMs…</div>}

            {!loading && !items.length ? <EmptyState title="No SBOMs" description="No SBOM documents match this scan/filter." /> : null}

            {!!items.length && (
                <div className="card table-card">
                    <table>
                        <thead>
                        <tr><th>ID</th><th>Image</th><th>Format</th><th>Created</th><th>Action</th></tr>
                        </thead>
                        <tbody>
                        {items.map((item) => (
                            <tr key={item.id}>
                                <td>{item.id}</td>
                                <td>{item.image}</td>
                                <td>{item.format}</td>
                                <td>{formatDate(item.created_at)}</td>
                                <td><Button variant="secondary" onClick={() => downloadSbom(scanId, item.id)}>Download</Button></td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            )}
        </section>
    );
}
