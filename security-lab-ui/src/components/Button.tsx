import type { ButtonHTMLAttributes, PropsWithChildren } from 'react';

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
    variant?: ButtonVariant;
}

export function Button({ children, className = '', variant = 'primary', ...props }: PropsWithChildren<ButtonProps>) {
    return (
        <button className={`btn btn--${variant} ${className}`.trim()} {...props}>
            {children}
        </button>
    );
}
