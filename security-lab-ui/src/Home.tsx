import React, {useState} from 'react'
import './style/App.css'
import './style/button.css'
import LoadImageModal from "./scan/LoadImageModal";
import ScanList from "./scan/ScanList";

function Home() {
    const [isLoaderOpen, setLoaderOpen] = useState<boolean>(false);
    const [isScanListOpen, setScanListOpen] = useState<boolean>(true);

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

                    <button
                        className="action-btn"
                        onClick={()=> isScanListOpen? setScanListOpen(false):setScanListOpen(true)}>
                        {isScanListOpen ? "hide scan list" : "show scan list"}
                    </button>
                </div>
                <div className='body-main'>
                    <ScanList isOpen={isScanListOpen}/>
                </div>
            </div>
        </div>
    );
}

export default Home;
