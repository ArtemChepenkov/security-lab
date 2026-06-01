import React, { useState } from 'react';
import {startScan} from '../../api/scan';
import { Button } from '../../components/Button';
import { Modal } from '../../components/Modal';

export function StartScanModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void; onStarted?: () => void }) {
    const [release, setRelease] = useState('');
    const [file, setFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    async function handleSubmit() {
        setError(null);

        if (!release.trim()) return setError('Введите имя scan/release.');
        if (!file) return setError('Выберите Helm chart .tgz.');

        try {
            setLoading(true);
            await startScan(release.trim(), file);
            setRelease('');
            setFile(null);
            onClose();
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to start scan');
        } finally {
            setLoading(false);
        }
    }

    return (
        <Modal title="Start image scan" isOpen={isOpen} onClose={onClose}>
            <form className="form" onSubmit={handleSubmit}>
                <label>
                    Release name
                    <input value={release} placeholder="payment-service" onChange={(event) => setRelease(event.target.value)} />
                </label>
                <label>
                    Helm chart archive
                    <input type="file" accept=".tgz" onChange={(event) => setFile(event.target.files?.[0] ?? null)} />
                </label>
                {error && <div className="alert alert--error">{error}</div>}
                <Button type="submit" disabled={loading}>{loading ? 'Starting…' : 'Start scan'}</Button>
            </form>
        </Modal>
    );
}
