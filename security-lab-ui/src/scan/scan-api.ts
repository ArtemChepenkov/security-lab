import {ScanInfo, ScanRow} from "./types";

const API_BASE = "http://130.193.53.6:8080/scan"

export async function scanImage(data: FormData): Promise<string> {
    const res = await fetch(`${API_BASE}/start`, {
        method: 'POST',
        body: data,
    });

    if(!res.ok) {
        const msg = res.text();
        console.error("Ошибка загрузки чарта: " + msg);
    }

    return res.json();
}

export async function getAllScans(): Promise<ScanRow[]> {
    const res = await fetch(`${API_BASE}/list`, {
        method: 'GET',
        headers: {
            "Content-Type": "application/json",
        }
    })

    if(!res.ok) {
        const msg = await res.text();
        console.error("Ошибка загрузки списка сканов: " + msg)
    }

    return res.json();
}

export async function getScan(scanId: string): Promise<ScanInfo> {
    const res = await fetch(`${API_BASE}/${scanId}`, {
        method: 'GET',
        headers: {
            "Content-Type": "application/json",
        }
    })

    if (!res.ok) {
        const msg = await res.text();
        console.error("Ошибка загрузки информации о скане: " + msg)
    }

    return res.json();
}