import { useEffect, useMemo, useRef, useState } from 'react';

export function NamespaceCombobox({
    value,
    options,
    onChange,
    placeholder,
}: {
    value: string;
    options: string[];
    onChange: (value: string) => void;
    placeholder?: string;
}) {
    const [open, setOpen] = useState(false);
    const wrapperRef = useRef<HTMLDivElement>(null);

    // Закрываем при клике вне компонента.
    useEffect(() => {
        function handleClickOutside(event: MouseEvent) {
            if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
                setOpen(false);
            }
        }
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const filtered = useMemo(() => {
        const needle = value.trim().toLowerCase();
        if (!needle) return options;
        return options.filter((ns) => ns.toLowerCase().includes(needle));
    }, [options, value]);

    return (
        <div className="combobox" ref={wrapperRef}>
            <input
                value={value}
                placeholder={placeholder}
                onChange={(event) => { onChange(event.target.value); setOpen(true); }}
                onFocus={() => setOpen(true)}
            />

            {open && filtered.length > 0 && (
                <ul className="combobox__menu">
                    {filtered.map((ns) => (
                        <li key={ns}>
                            <button
                                type="button"
                                className="combobox__option"
                                onClick={() => { onChange(ns); setOpen(false); }}
                            >
                                {ns}
                            </button>
                        </li>
                    ))}
                </ul>
            )}
        </div>
    );
}
