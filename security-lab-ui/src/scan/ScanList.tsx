import React, {useEffect, useState} from "react";
import {getAllScans} from "./scan-api";
import '../style/button.css'
import '../style/scan-list.css'
import {ScanRow} from "./types";

interface ScanListProps {
    isOpen: boolean;
    onSelectScan: (scanId: string) => void;
}

const ScanList: React.FC<ScanListProps> = ({isOpen, onSelectScan})=> {

    const [data, setData] = useState<ScanRow[]>([]);
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        const loadData = async () => {
            try {
                setLoading(true);
                const scans = await getAllScans();
                setData(scans);
            } catch (error) {
                console.error(error);
            } finally {
                setLoading(false);
            }
        };

        loadData();
    }, []);

    if (!isOpen) return null;

    if (loading) {
        return <div className="scan-list">Загрузка...</div>;
    }

    return (
        <div className="scan-list">
            <table className="scan-table">
                <thead>
                <tr>
                    <th>Scan ID</th>
                    <th>Scan name</th>
                    <th>Namespace</th>
                    <th>Status</th>
                </tr>
                </thead>

                <tbody>
                {data.map(
                    ([scanId, __, namespase, name, status]) => {

                        return (
                            <tr
                                key={scanId}
                                className="scan-row"
                            >
                                <td>
                                    <button
                                        className="scan-button"
                                        onClick={() => onSelectScan(scanId)}
                                    >
                                        {scanId}
                                    </button>
                                </td>

                                <td>{name}</td>
                                <td>{namespase}</td>

                                <td>
                                    <span className="status-badge">
                                        {status}
                                    </span>
                                </td>
                            </tr>
                        );
                    }
                )}
                </tbody>
            </table>
        </div>
    );

}

export default ScanList;