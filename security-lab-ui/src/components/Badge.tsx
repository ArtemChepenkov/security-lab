import type { FindingSeverity } from '../types';

export function StatusBadge({ status }: { status: string }) {
    return <span className="badge" data-status={status.toLowerCase()}>{status}</span>;
}

export function SeverityBadge({ severity }: { severity: FindingSeverity }) {
    return <span className="severity" data-severity={severity.toLowerCase()}>{severity}</span>;
}
