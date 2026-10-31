// Small shadcn/ui-style primitives, kept local rather than adding a component framework.
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type { ButtonHTMLAttributes, HTMLAttributes } from "react";

export function cn(...values: ClassValue[]) {
  return twMerge(clsx(values));
}

const buttonVariants = cva("button", {
  variants: {
    variant: {
      outline: "button-outline",
      ghost: "button-ghost",
      default: "button-primary",
    },
    size: { default: "", icon: "button-icon", small: "button-small" },
  },
  defaultVariants: { variant: "outline", size: "default" },
});

export function Button({
  asChild = false,
  variant,
  size,
  className,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants> & { asChild?: boolean }) {
  const Component = asChild ? Slot : "button";
  return (
    <Component
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  );
}

export function Badge({
  className,
  ...props
}: HTMLAttributes<HTMLSpanElement>) {
  return <span className={cn("badge", className)} {...props} />;
}
