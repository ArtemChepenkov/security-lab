import React, {useEffect, useMemo, useState} from "react";
import {FindingSeverity, ScanInfo} from "./types";
import { getScan } from "./scan-api";
import '../style/scan-res.css'

interface Props {
    scanId: string;
}

const severityOptions: Array<FindingSeverity | "ALL"> = [
    "ALL",
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL"
];

export const ScanResults: React.FC<Props> = ({ scanId }) => {
    const [data, setData] = useState<ScanInfo | null>(null);

    const [loading, setLoading] = useState(false);

    const [severityFilter, setSeverityFilter] = useState< FindingSeverity | "ALL" >("ALL");

    useEffect(() => {
        const loadScan = async () => {
            try {
                setLoading(true);

                const scan =
                    await getScan(scanId);

                setData(scan);
            } catch (error) {
                console.error(error);
            } finally {
                setLoading(false);
            }
        };

        loadScan();
    }, [scanId]);

    const filteredFindings = useMemo(() => {
        if (!data) return [];

        if (severityFilter === "ALL") {
            return data.findings;
        }

        return data.findings.filter(
            ([, severity]) =>
                severity === severityFilter
        );
    }, [data, severityFilter]);

    if (loading) {
        return <div className="scan-results">Загрузка...</div>;
    }

    if (!data) {
        return <div>Нет данных</div>;
    }

    console.log(data)
    const [, , namespace, scanName] = data.scan;

    return (
        <div className="scan-results">
            <div className="scan-results__info">
                <div className="scan-results__header">
                    <div className="llll">
                        <label>Name: {scanName}</label>
                        <label>Namespace: {namespace}</label>
                        <div className="image">
                            Image:
                            {data.images.map(([image]) => (
                                <label key={image}>{image}</label>
                            ))}
                        </div>
                    </div>

                    <button className="action-btn">
                        Compare
                    </button>
                </div>
            </div>

            <div className="scan-results__filter">
                <label> Filter by severity:</label>

                <select
                    value={severityFilter}
                    onChange={(e) =>
                        setSeverityFilter(
                            e.target.value as
                                | FindingSeverity
                                | "ALL"
                        )
                    }
                >
                    {severityOptions.map((severity) => (
                        <option
                            key={severity}
                            value={severity}
                        >
                            {severity}
                        </option>
                    ))}
                </select>
            </div>

            <div className="scan-results__table-wrapper">
                <table className="scan-results__table">
                    <thead>
                    <tr>
                        <th>Scanner</th>
                        <th>Severity</th>
                        <th>Description</th>
                    </tr>
                    </thead>

                    <tbody>
                    {filteredFindings.map(
                        (
                            [
                                scanner,
                                severity,
                                _,
                                description
                            ],
                            index
                        ) => (
                            <tr key={index}>
                                <td>{scanner}</td>

                                <td>
                                    <span
                                        className={`severity severity--${severity.toLowerCase()}`}
                                    >
                                        {severity}
                                    </span>
                                </td>

                                <td>{description}</td>
                            </tr>
                        )
                    )}
                    </tbody>
                </table>
            </div>
        </div>
    );
};