import { Button } from './Button';

const PAGE_SIZES = [10, 20, 50, 100];

export function Pagination({ page, pageSize, total, onPageChange, onPageSizeChange }: {
    page: number;
    pageSize: number;
    total: number;
    onPageChange: (page: number) => void;
    onPageSizeChange: (size: number) => void;
}) {
    const pages = Math.max(1, Math.ceil(total / pageSize));

    return (
        <div className="pagination">
            <Button variant="secondary" disabled={page <= 1} onClick={() => onPageChange(Math.max(1, page - 1))}>Prev</Button>
            <span>Page {page} / {pages} · Total {total}</span>
            <Button variant="secondary" disabled={page >= pages} onClick={() => onPageChange(page + 1)}>Next</Button>
            <select value={pageSize} onChange={(event) => onPageSizeChange(Number(event.target.value))}>
                {PAGE_SIZES.map((size) => <option key={size} value={size}>{size} / page</option>)}
            </select>
        </div>
    );
}
