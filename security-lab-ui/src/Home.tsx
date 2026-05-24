import React, {useState} from 'react'
import './style/App.css'
import './style/button.css'
import LoadImageModal from "./scan/LoadImageModal";
import ScanList from "./scan/ScanList";
import {ScanResults} from "./scan/ScanPage";

function Home() {
    const [isLoaderOpen, setLoaderOpen] = useState<boolean>(false);
    const [isScanListOpen, setScanListOpen] = useState<boolean>(true);
    const [selectedScanId, setSelectedScanId] = useState<string | null>(null);


    return (
        <div className="App">
            <header className="header">
                <label className="name">
                    Security Lab
                </label>
            </header>
            <div className="body">
                <div className='body-buttons'>
                    <button
                        className="action-btn"
                        onClick={()=> setLoaderOpen(true)}>
                        scan image
                    </button>

                    <LoadImageModal
                        isOpen={isLoaderOpen}
                        onClose={() => setLoaderOpen(false)
                        }/>

                    <button className="action-btn">
                        scan kube
                    </button>

                    {!selectedScanId && (
                        <button
                            className="action-btn"
                            onClick={() =>
                                setScanListOpen(
                                    !isScanListOpen
                                )
                            }
                        >
                            {isScanListOpen
                                ? "hide scan list"
                                : "show scan list"}
                        </button>
                    )}

                    {selectedScanId && (
                        <button
                            className="action-btn"
                            onClick={() =>
                                setSelectedScanId(
                                    null
                                )
                            }
                        >
                            back
                        </button>
                    )}
                </div>
                <div className='body-main'>
                    {!selectedScanId ? (
                        <ScanList
                            isOpen={isScanListOpen}
                            onSelectScan={
                                setSelectedScanId
                            }
                        />
                    ) : (
                        <ScanResults
                            scanId={
                                selectedScanId
                            }
                        />
                    )}
                </div>
            </div>
        </div>
    );
}

export default Home;
