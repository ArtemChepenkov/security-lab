import type { PropsWithChildren } from 'react';
import { Button } from './Button';

export function Modal({ title, isOpen, onClose, children }: PropsWithChildren<{ title: string; isOpen: boolean; onClose: () => void }>) {
    if (!isOpen) return null;

    return (
        <div className="modal-backdrop" onMouseDown={onClose}>
            <section className="modal" onMouseDown={(event) => event.stopPropagation()} role="dialog" aria-modal="true">
                <header className="modal__header">
                    <h2>{title}</h2>
                    <Button variant="ghost" onClick={onClose} aria-label="Close">×</Button>
                </header>
                <div className="modal__body">{children}</div>
            </section>
        </div>
    );
}
