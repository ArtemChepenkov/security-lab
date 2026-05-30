export function formatDate(value?: string | number | null): string {
    if (!value) return '—';
    const date = typeof value === 'number' && value < 10_000_000_000 ? new Date(value * 1000) : new Date(value);
    if (Number.isNaN(date.getTime())) return '—';
    return date.toLocaleString();
}

export function formatNumber(value?: number | null): string {
    return value === null || value === undefined ? '—' : String(value);
}

export function plural(value: number, one: string, many: string): string {
    return `${value} ${value === 1 ? one : many}`;
}
