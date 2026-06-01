import {useState, useMemo, useEffect} from "react";
import {EmptyState} from "../../components/EmptyState";
import {Button} from "../../components/Button";
import {getScanDiff, getScans} from "../../api/scan";
import {DiffResponse, ScanItem} from "../../types";
import {formatDate} from "../../utils/format";

export function CompareScansPage() {
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(true);
    const [comparing, setComparing] = useState(false);

    const [scans, setScans] = useState<ScanItem[]>([]);
    const [leftScanId, setLeftScanId] = useState("");
    const [rightScanId, setRightScanId] = useState("");
    const [diff, setDiff] = useState<DiffResponse | null>(null);

    useEffect(() => {
        let alive = true;

        setLoading(true);
        setError(null);

        getScans(1, 200)
            .then((response) => {
                if (!alive) return;

                const items = response.items || [];
                setScans(items);

                if (items[0]) {
                    setLeftScanId(items[0].id);
                }

                if (items[1]) {
                    setRightScanId(items[1].id);
                }
            })
            .catch((err) => {
                if (!alive) return;
                setError(err instanceof Error ? err.message : "Failed to load scans");
            })
            .finally(() => {
                if (alive) {
                    setLoading(false);
                }
            });

        return () => {
            alive = false;
        };
    }, []);

    const selectedLeft = useMemo(
        () => scans.find((scan) => scan.id === leftScanId),
        [scans, leftScanId]
    );

    const selectedRight = useMemo(
        () => scans.find((scan) => scan.id === rightScanId),
        [scans, rightScanId]
    );

    async function handleCompare() {
        if (!leftScanId || !rightScanId) {
            setError("Choose scans for comparing");
            return;
        }

        if (leftScanId === rightScanId) {
            setError("You need to compare two different scans");
            return;
        }

        try {
            setError(null);
            setComparing(true);
            const res = await getScanDiff(leftScanId, rightScanId);
            setDiff(res);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to compare scans");
        } finally {
            setComparing(false);
        }
    }

    return (
        <section className='page'>
            <div className='page__header'>
                <div>
                    <p className="eyebrow">Compare</p>
                </div>
            </div>

            {error && <div className='alert alert--error'>{error}</div> }
            {loading && <div className="loader">Loading scans…</div>}

            {!loading && scans.length < 2 ? (
                <EmptyState
                    title="Not enough scans"
                    description="Для сравнения нужно минимум два скана."
                />
            ) : null}

            {!loading && scans.length >= 2 ? (
                <>
                    <div className='card compare-card'>
                        <label>
                            First scan
                            <select
                                value={leftScanId}
                                onChange={(e) => setLeftScanId(e.target.value)}
                            >
                                {scans.map((scan) => (
                                    <option key={scan.id} value={scan.id}>
                                        {scan.release || "No name"}  - {scan.id} - {formatDate(scan.ts)}
                                    </option>
                                ))}
                            </select>
                        </label>

                        <label>
                            Second scan
                            <select
                                value={rightScanId}
                                onChange={(e) => setRightScanId(e.target.value)}
                            >
                                {scans.map((scan) => (
                                    <option key={scan.id} value={scan.id}>
                                        {scan.release || "No name"}  - {scan.id} - {formatDate(scan.ts)}
                                    </option>
                                ))}
                            </select>
                        </label>

                        <Button onClick={handleCompare} disabled={comparing}>
                            {comparing? "Comparing..." : "Compare"}
                        </Button>
                    </div>

                    {selectedLeft && selectedRight && (
                        <div className="summary-grid">
                            <article className="metric-card">
                                <span>First</span>
                                <strong>{selectedLeft.release || "-"}</strong>
                            </article>
                            <article className="metric-card">
                                <span>Second</span>
                                <strong>{selectedRight.release || "-"}</strong>
                            </article>
                            <article className="metric-card">
                                <span>Fixed</span>
                                <strong>{diff?.fixed.length ?? "-"}</strong>
                            </article>
                            <article className="metric-card">
                                <span>New</span>
                                <strong>{diff?.new.length ?? "-"}</strong>
                            </article>
                        </div>
                    )}

                    {diff && (
                        <div className="compare-grid">
                            <div className="card table-card table-card--half">
                                <div className="table-toolbar">
                                    <h2>Fixed in second scan</h2>
                                </div>

                                {!diff.fixed.length ? (
                                    <EmptyState
                                        title="Nothing fixed"
                                        description=""
                                    />
                                ) : (
                                    <div className='table-scroll'>
                                        <table>
                                            <tbody>
                                            {diff.fixed.map((item) => (
                                                <tr key={item}>
                                                    <td>{item}</td>
                                                </tr>
                                            ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>

                            <div className="card table-card table-card--half">
                                <div className="table-toolbar">
                                    <h2>New in second scan</h2>
                                </div>

                                {!diff.new.length ? (
                                    <EmptyState title="No new findings"/>
                                ) : (
                                    <div className="table-scroll">
                                        <table>
                                            <tbody>
                                            {diff.new.map((item) => (
                                                <tr key={item}>
                                                    <td>{item}</td>
                                                </tr>
                                            ))}
                                            </tbody>
                                        </table>
                                    </div>
                                )}
                            </div>
                        </div>
                    )}
                </>
            ) : null}

        </section>
    )
}