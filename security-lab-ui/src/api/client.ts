const DEFAULT_API_URL = 'http://130.193.53.6:8080';

export const API_URL = process.env.REACT_APP_API_URL || DEFAULT_API_URL;

export class ApiError extends Error {
    constructor(message: string, public status: number) {
        super(message);
        this.name = 'ApiError';
    }
}

export async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(`${API_URL}${path}`, init);

    if (!response.ok) {
        const message = await response.text().catch(() => response.statusText);
        throw new ApiError(message || response.statusText, response.status);
    }

    if (response.status === 204) return undefined as T;
    return await response.json() as Promise<T>;
}

export async function download(path: string, filename: string): Promise<void> {
    const response = await fetch(`${API_URL}${path}`);

    if (!response.ok) {
        throw new ApiError(await response.text(), response.status);
    }

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    window.URL.revokeObjectURL(url);
}
