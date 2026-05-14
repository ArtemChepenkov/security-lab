const API_BASE = "http://130.193.53.6:8080/scan"

export async function scanImage(data: FormData): Promise<any> {
    const res = await fetch(`${API_BASE}/start`, {
        method: 'POST',
        body: data,
    });
}

export type ScanRow = [
    string,
    number,
    string,
    string,
    string
];

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