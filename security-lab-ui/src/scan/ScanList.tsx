import React, {useEffect, useState} from "react";
import {getAllScans, ScanRow} from "./scan-api";
import '../style/button.css'
import '../style/scan-list.css'

interface ScanListProps {
    isOpen: boolean;
}

const ScanList: React.FC<ScanListProps> = ({isOpen})=> {

    const [data, setData] = useState<ScanRow[]>([]);
    const [loading, setLoading] = useState(false);
    const [activeRow, setActiveRow] = useState<string | null>(null);

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
                    <th>Status</th>
                </tr>
                </thead>

                <tbody>
                {data.map(
                    ([scanId, __, _, name, status]) => {
                        const isActive =
                            activeRow === scanId;
                        return (
                            <tr
                                key={scanId}
                                className="scan-row"
                            >
                                <td>
                                    <button
                                        className="scan-button"
                                        onClick={() =>
                                            setActiveRow(
                                                isActive
                                                    ? null
                                                    : scanId
                                            )
                                        }
                                    >
                                        {scanId}
                                    </button>
                                </td>

                                <td>{name}</td>

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