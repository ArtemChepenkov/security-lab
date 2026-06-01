import { useState } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';

import { AppLayout } from './layout/AppLayout';
import { StartScanModal } from './features/scans/StartScanModal';
import { DashboardPage } from './features/scans/DashboargPage';
import { ScanDetailsPage } from './features/scans/ScanDetailsPage';
import { ScanList} from './features/scans/ScanList';
import { SbomPage } from './features/sbom/SbomPage';
import { VulnerabilitiesPage } from './features/vulnerabilities/VulnerabilitiesPage';
import {CompareScansPage} from "./features/scans/CompareScansPage";
import { K8sScanPage } from './features/scans/K8sScanPage';
import { ClusterScanPage } from './features/scans/ClusterScanPage';

import './styles/app.css';

export default function App() {
    const [scanModalOpen, setScanModalOpen] = useState(false);

    return (
        <BrowserRouter>
            <Routes>
                <Route element={<AppLayout onOpenScanModal={() => setScanModalOpen(true)} />}>
                    <Route index element={<DashboardPage />} />
                    <Route path="scans" element={<ScanList />} />
                    <Route path="scans/k8s" element={<K8sScanPage />} />
                    <Route path="scans/k8s/:scanId" element={<K8sScanPage />} />
                    <Route path="scans/cluster" element={<ClusterScanPage />} />
                    <Route path="scans/cluster/:scanId" element={<ClusterScanPage />} />
                    <Route path="scans/compare" element={<CompareScansPage/>}/>
                    <Route path="scans/:scanId" element={<ScanDetailsPage />} />
                    <Route path="scans/:scanId/sbom" element={<SbomPage />} />
                    <Route path="vulnerabilities" element={<VulnerabilitiesPage />} />
                    <Route path="*" element={<Navigate to="/" replace />} />
                </Route>
            </Routes>

            <StartScanModal isOpen={scanModalOpen} onClose={() => setScanModalOpen(false)} />
        </BrowserRouter>
    );
}
