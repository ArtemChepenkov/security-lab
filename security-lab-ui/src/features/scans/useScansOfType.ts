import { useCallback, useEffect, useState } from 'react';
import { getScans } from '../../api/scan';
import type { ScanItem } from '../../types';

export function useScansOfType(predicate: (scan: ScanItem) => boolean) {
    const [scans, setScans] = useState<ScanItem[]>([]);
    const [reloadKey, setReloadKey] = useState(0);

    const reload = useCallback(() => setReloadKey((k) => k + 1), []);

    useEffect(() => {
        let alive = true;
        let timer: number | undefined;

        async function load() {
            try {
                const res = await getScans(1, 200, 'all');
                if (!alive) return;
                const filtered = (res.items || []).filter(predicate);
                setScans(filtered);

                const hasRunning = filtered.some((s) =>
                    ['running', 'created'].includes((s.status || '').toLowerCase()),
                );
                if (hasRunning) {
                    timer = window.setTimeout(load, 5000);
                }
            } catch {
                // тихо игнорируем — список не критичен
            }
        }

        load();
        return () => {
            alive = false;
            if (timer) window.clearTimeout(timer);
        };
    }, [reloadKey, predicate]);

    return { scans, reload };
}
