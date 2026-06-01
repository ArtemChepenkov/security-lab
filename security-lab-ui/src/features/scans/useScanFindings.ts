import { useEffect, useState } from 'react';
import { getScanDetails } from '../../api/scan';
import type { ScanDetailsResponse } from '../../types';

/**
 * Загружает детали скана и автоматически опрашивает бэкенд, пока скан
 * в статусе running/created. Используется на страницах k8s и cluster сканов.
 */
export function useScanFindings(scanId: string | null) {
    const [data, setData] = useState<ScanDetailsResponse | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!scanId) {
            setData(null);
            setError(null);
            return;
        }

        let alive = true;
        let timer: number | undefined;

        async function load() {
            try {
                const res = await getScanDetails(scanId!, undefined, undefined, undefined, 1, 200);
                if (!alive) return;
                setData(res);
                setError(null);

                const status = res.scan.status?.toLowerCase();
                if (status === 'running' || status === 'created') {
                    timer = window.setTimeout(load, 4000);
                }
            } catch (err) {
                if (!alive) return;
                setError(err instanceof Error ? err.message : 'Failed to load scan');
            } finally {
                if (alive) setLoading(false);
            }
        }

        setLoading(true);
        load();

        return () => {
            alive = false;
            if (timer) window.clearTimeout(timer);
        };
    }, [scanId]);

    return { data, loading, error };
}
