import { NavLink, Outlet } from 'react-router-dom';
import { Button } from '../components/Button';

export function AppLayout({ onOpenScanModal }: { onOpenScanModal: () => void }) {
    return (
        <div className="app-shell">
            <aside className="sidebar">
                <div className="brand">
                    <div>
                        <strong>Security Lab</strong>
                    </div>
                </div>

                <Button className="sidebar__cta" onClick={onOpenScanModal}>Scan image</Button>

                <nav className="nav">
                    <NavLink to="/" end>Dashboard</NavLink>
                    <NavLink to="/scans" end>Scans</NavLink>
                    <NavLink to="/scans/k8s">Namespaces scan</NavLink>
                    <NavLink to="/scans/cluster">Cluster scan</NavLink>
                    <NavLink to="/scans/compare">Compare</NavLink>
                </nav>
            </aside>

            <main className="main">
                <Outlet />
            </main>
        </div>
    );
}
