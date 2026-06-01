import { StatusBadge } from '../../components/Badge';
import { EmptyState } from '../../components/EmptyState';
import type { ScanItem } from '../../types';
import { formatDate } from '../../utils/format';

export function LaunchedScansTable({
    scans,
    activeId,
    onSelect,
}: {
    scans: ScanItem[];
    activeId?: string;
    onSelect: (scanId: string) => void;
}) {
    return (
        <div className="card table-card table-card--full">
            <div className="table-toolbar">
                <h2>Запущенные сканы</h2>
            </div>

            {!scans.length ? (
                <EmptyState title="Пока нет сканов" description="Запусти скан выше — он появится здесь." />
            ) : (
                <div className="table-scroll">
                    <table>
                        <thead>
                        <tr>
                            <th>Scan</th>
                            <th>Target</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th></th>
                        </tr>
                        </thead>
                        <tbody>
                        {scans.map((scan) => (
                            <tr key={scan.id} data-active={scan.id === activeId}>
                                <td>{scan.id}</td>
                                <td>{scan.namespace || scan.release || '—'}</td>
                                <td><StatusBadge status={scan.status} /></td>
                                <td>{formatDate(scan.ts)}</td>
                                <td>
                                    <button className="link-button" type="button" onClick={() => onSelect(scan.id)}>
                                        Показать результаты
                                    </button>
                                </td>
                            </tr>
                        ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
