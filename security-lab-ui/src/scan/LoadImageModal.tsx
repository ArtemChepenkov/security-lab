import React, {useRef, useState} from "react"
import '../style/button.css'
import '../style/modal.css'
import {scanImage} from "./scan-api";

interface LoadImageModalProps {
    isOpen: boolean;
    onClose: () => void;
}

const LoadImageModal: React.FC<LoadImageModalProps> = ({isOpen, onClose})=> {
    const fileInputRef = useRef<HTMLInputElement>(null);
    const [imageName, setImageName] = useState<string>('');

    if (!isOpen) return null;

    const handleSubmit = async () => {
        const files = fileInputRef.current?.files;
        if (!files || files.length === 0) {
            alert('Выберите файл .tgz');
            return;
        }
        const file = files[0];

        if (!imageName.trim()) {
            alert('Введите имя образа');
            return;
        }

        const formData = new FormData();
        formData.append('chart', file);
        formData.append('release', imageName);

        scanImage(formData);
    }


        return (
        <div className="modal-overlay">
            <div className="modal-window"
                 onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <label>Загрузка образа</label>
                    <button className="close-btn" onClick={onClose}> X </button>
                </div>
                <div className="modal-body">
                    <input
                        ref={fileInputRef}
                        type="file"
                        accept=".tgz"
                    />

                    <input
                        type="text"
                        placeholder="Enter scan name"
                        onChange={(e)=> setImageName(e.target.value)}
                    />

                    <button className="action-btn">start scanning</button>
                </div>
            </div>
        </div>
    )
}

export default LoadImageModal;