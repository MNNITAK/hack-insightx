/**
 * Simple utility function to merge CSS classes
 * Basic implementation for class combination
 */

export function cn(...classes: (string | undefined | null | false)[]): string {
  return classes.filter(Boolean).join(' ');
}